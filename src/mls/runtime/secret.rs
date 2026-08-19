//! Account- and device-scoped MLS snapshot-secret management.
//!
//! The snapshot secret is account-scoped and shared by every device of the
//! account; it is recoverable via the user's recovery passphrase. The `_local`
//! rotation helpers prepare new wrapping material without mutating local state
//! so callers can upload server-side backups before committing.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::MlsRuntimeError;
use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError};

const ACCOUNT_MLS_SECRET_PREFIX: &str = "inkson.mls_snapshot.account_secret";
const ACCOUNT_MLS_SECRET_VERIFIED_MARKER: &str = "verified";
pub const ACCOUNT_MLS_SECRET_CURRENT_VERSION: u32 = 1;
const ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION: u32 = 32;
const MLS_KEY_PACKAGE_IDENTITY_STATE_PREFIX: &str = "inkson.mls_key_package.identity_state.v1";
// Direct Conversation peer claims must use single-use KeyPackages, so every
// device republishes an ordinary package after each successfully applied
// Welcome.
const MLS_KEY_PACKAGE_PUBLISH_MARKER_PREFIX: &str = "inkson.mls_key_package.publish_marker.v1";
/// Per-(actor, device) X25519 keypair used to receive HPKE-sealed
/// `history_secret`s in a `ak.realm_key.share`. This device advertises the
/// public half as `recipient_hpke_public_key` in a `ak.realm_key.request` and
/// opens the sealed reply with the private half.
///
/// TODO(history-share): ideally the receiver would advertise (and open with)
/// the X25519 init-key private half of its published MLS KeyPackage so a
/// provider can seal proactively at admission time from the claim alone.
/// OpenMLS does not surface that raw private scalar through the current SDK,
/// so we mint a dedicated, persisted device HPKE keypair instead. The provider
/// therefore can only seal once the receiver has advertised this key (the
/// request path); the admission-time proactive push is best-effort and skipped
/// when the invitee's HPKE public key is not yet known.
const DEVICE_HPKE_PRIVATE_KEY_PREFIX: &str = "inkson.device_hpke_x25519.private.v1";

/// Stored account-scoped MLS snapshot secret plus the local key version that
/// carried it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAccountMlsSecret {
    pub version: u32,
    pub secret: String,
}

/// Local account-scoped secret rotation material. The network upload path uses
/// `new_secret` to wrap the new account-secret backup, then commits this
/// material locally once the server-side backups have landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMlsSecretRotation {
    pub previous_version: u32,
    pub new_version: u32,
    pub new_secret: String,
    pub rewrapped_snapshots: BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    /// COR-12: realms whose snapshot could not be decrypted with the previous
    /// secret (corrupt / format-drifted local data) and were therefore SKIPPED
    /// instead of aborting the whole rotation. `(realm_id, error)` pairs so the
    /// caller can surface a partial-success report. Empty on a clean rotation.
    pub failed_realms: Vec<(String, String)>,
}

/// Account-scoped storage key for a specific MLS snapshot-secret version.
pub fn account_mls_secret_key_for_version(actor_id: &str, version: u32) -> String {
    format!(
        "{ACCOUNT_MLS_SECRET_PREFIX}.v{}.{}",
        version,
        actor_id.trim()
    )
}

/// Default write key for the account-scoped MLS snapshot secret shared by every
/// device of the account. Recoverable via the user's recovery passphrase.
pub fn account_mls_secret_key(actor_id: &str) -> String {
    account_mls_secret_key_for_version(actor_id, ACCOUNT_MLS_SECRET_CURRENT_VERSION)
}

fn validate_account_secret_inputs<'a>(
    actor_id: &'a str,
    secret: &str,
) -> Result<&'a str, SecureKeyStoreError> {
    let actor = actor_id.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_id is required for MLS snapshot secret".to_owned(),
        ));
    }
    if secret.trim().is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "account MLS secret must not be empty".to_owned(),
        ));
    }
    Ok(actor)
}

/// Store (or overwrite) a specific version of the account-scoped MLS snapshot
/// secret.
pub fn store_account_mls_secret_version(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    version: u32,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    if version == 0 || version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(SecureKeyStoreError::Backend(format!(
            "account MLS secret version {version} is outside the supported scan range"
        )));
    }
    let actor = validate_account_secret_inputs(actor_id, secret)?;
    store.store_secret(&account_mls_secret_key_for_version(actor, version), secret)
}

/// Replace all locally-known account MLS secret versions with one recovered
/// from the server backup.
///
/// Recovery must win over a stale local secret that may have been generated by
/// a previous incomplete bootstrap. Since [`load_account_mls_secret`] picks the
/// highest version, keeping a newer-but-wrong local version would make the
/// recovered backup ineffective.
pub fn replace_account_mls_secret_version(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    version: u32,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    if version == 0 || version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(SecureKeyStoreError::Backend(format!(
            "account MLS secret version {version} is outside the supported scan range"
        )));
    }
    let actor = validate_account_secret_inputs(actor_id, secret)?;
    store.store_secret(&account_mls_secret_key_for_version(actor, version), secret)?;
    for existing_version in 1..=ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        if existing_version != version {
            store.delete_secret(&account_mls_secret_key_for_version(actor, existing_version))?;
        }
    }
    Ok(())
}

/// Store (or overwrite) the default/current account-scoped MLS snapshot secret.
/// Used by the recovery import path after unwrapping the recovery vault.
pub fn store_account_mls_secret(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    store_account_mls_secret_version(store, actor_id, ACCOUNT_MLS_SECRET_CURRENT_VERSION, secret)
}

/// Load the highest local account-secret version currently present.
pub fn load_account_mls_secret(
    store: &dyn SecureKeyStore,
    actor_id: &str,
) -> Result<Option<StoredAccountMlsSecret>, SecureKeyStoreError> {
    let actor = actor_id.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_id is required for MLS snapshot secret".to_owned(),
        ));
    }
    for version in (1..=ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION).rev() {
        let key = account_mls_secret_key_for_version(actor, version);
        if let Some(secret) = store.get_secret(&key)?
            && !secret.trim().is_empty()
        {
            return Ok(Some(StoredAccountMlsSecret { version, secret }));
        }
    }
    Ok(None)
}

fn account_mls_secret_verified_key(actor_id: &str) -> String {
    format!(
        "{ACCOUNT_MLS_SECRET_PREFIX}.{ACCOUNT_MLS_SECRET_VERIFIED_MARKER}.v1.{}",
        actor_id.trim()
    )
}

/// Mark the active account secret as proven to belong to the server recovery
/// chain. Only a successful backup upload or recovery import may set this.
pub fn mark_account_mls_secret_verified(
    store: &dyn SecureKeyStore,
    actor_id: &str,
) -> Result<(), SecureKeyStoreError> {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_id is required for account-secret verification".to_owned(),
        ));
    }
    store.store_secret(&account_mls_secret_verified_key(actor_id), "verified")
}

/// Whether this device has proved that its local account secret belongs to
/// the server recovery chain. A freshly generated bootstrap secret is false.
pub fn account_mls_secret_verified(
    store: &dyn SecureKeyStore,
    actor_id: &str,
) -> Result<bool, SecureKeyStoreError> {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return Ok(false);
    }
    Ok(store
        .get_secret(&account_mls_secret_verified_key(actor_id))?
        .as_deref()
        == Some("verified"))
}

fn generate_account_mls_secret() -> Result<String, SecureKeyStoreError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom: {err}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Load (or create) the account-scoped MLS snapshot secret.
///
/// Resolution order:
///   a. the highest existing versioned account secret is returned as-is;
///   b. otherwise a fresh random 32-byte secret is generated, stored under the
///      current account key, and returned.
pub fn load_or_create_account_mls_secret(
    store: &dyn SecureKeyStore,
    actor_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let actor = actor_id.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_id is required for MLS snapshot secret".to_owned(),
        ));
    }
    if let Some(existing) = load_account_mls_secret(store, actor)? {
        return Ok(existing.secret);
    }
    let secret = generate_account_mls_secret()?;
    store_account_mls_secret(store, actor, &secret)?;
    Ok(secret)
}

/// Load-or-create the account MLS secret and await its durable persistence.
///
/// [`load_or_create_account_mls_secret`] writes through the sync store surface;
/// on wasm the IndexedDB commit behind that write is a detached background task
/// that a page unload silently drops. State persisted under this secret
/// (the creator's epoch-0 snapshot, a first applied Welcome) goes through the
/// durable-awaiting account-state writer, so the secret could reach disk AFTER
/// the snapshot it wraps — or never. A reload in that window leaves a snapshot
/// no local secret can open, which reads as "no account MLS secret" and
/// dead-locks every later encrypted write on this device. Callers that are
/// about to persist secret-wrapped state must use this variant so the secret
/// is durably stored first.
pub async fn ensure_account_mls_secret_durable(
    store: &dyn SecureKeyStore,
    actor_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let actor = actor_id.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_id is required for MLS snapshot secret".to_owned(),
        ));
    }
    if let Some(existing) = load_account_mls_secret(store, actor)? {
        // Re-commit the already-visible value: if the creation-time background
        // write was lost to an unload, this is the retry that lands it.
        store
            .store_secret_durable(
                &account_mls_secret_key_for_version(actor, existing.version),
                &existing.secret,
            )
            .await?;
        return Ok(existing.secret);
    }
    let secret = generate_account_mls_secret()?;
    store
        .store_secret_durable(&account_mls_secret_key(actor), &secret)
        .await?;
    // Concurrent first-creation is last-write-wins on the store; re-read so
    // every caller converges on the value that actually landed.
    if let Some(landed) = load_account_mls_secret(store, actor)? {
        return Ok(landed.secret);
    }
    Ok(secret)
}

pub fn mls_key_package_identity_state_key(
    actor_id: &str,
    device_id: &str,
    key_package_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let actor = actor_id.trim();
    let device = device_id.trim();
    let key_package = key_package_id.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_id is required for MLS KeyPackage identity state".to_owned(),
        ));
    }
    if device.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "device_id is required for MLS KeyPackage identity state".to_owned(),
        ));
    }
    if key_package.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "key_package_id is required for MLS KeyPackage identity state".to_owned(),
        ));
    }
    Ok(format!(
        "{MLS_KEY_PACKAGE_IDENTITY_STATE_PREFIX}.{actor}.{device}.{key_package}"
    ))
}

pub fn store_mls_key_package_identity_state(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    key_package_id: &str,
    serialized_state: &[u8],
) -> Result<(), SecureKeyStoreError> {
    if serialized_state.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "MLS KeyPackage identity state must not be empty".to_owned(),
        ));
    }
    let key = mls_key_package_identity_state_key(actor_id, device_id, key_package_id)?;
    let encoded = URL_SAFE_NO_PAD.encode(serialized_state);
    store.store_secret(&key, &encoded)
}

/// Durable variant of [`store_mls_key_package_identity_state`].
pub async fn store_mls_key_package_identity_state_durable(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    key_package_id: &str,
    serialized_state: &[u8],
) -> Result<(), SecureKeyStoreError> {
    if serialized_state.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "MLS KeyPackage identity state must not be empty".to_owned(),
        ));
    }
    let key = mls_key_package_identity_state_key(actor_id, device_id, key_package_id)?;
    store
        .store_secret_durable(&key, &URL_SAFE_NO_PAD.encode(serialized_state))
        .await
}

pub fn load_mls_key_package_identity_state(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    key_package_id: &str,
) -> Result<Option<Vec<u8>>, SecureKeyStoreError> {
    let key = mls_key_package_identity_state_key(actor_id, device_id, key_package_id)?;
    let secret = store.get_secret(&key)?;
    let Some(secret) = secret else {
        return Ok(None);
    };
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .map(Some)
        .map_err(|err| {
            SecureKeyStoreError::Backend(format!("decode MLS KeyPackage identity state: {err}"))
        })
}

pub fn delete_mls_key_package_identity_state(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    key_package_id: &str,
) -> Result<(), SecureKeyStoreError> {
    let key = mls_key_package_identity_state_key(actor_id, device_id, key_package_id)?;
    store.delete_secret(&key)
}

fn secure_key_component(value: &str, label: &str) -> Result<String, SecureKeyStoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SecureKeyStoreError::Backend(format!(
            "{label} is required for MLS KeyPackage publish marker"
        )));
    }
    Ok(URL_SAFE_NO_PAD.encode(trimmed.as_bytes()))
}

pub fn mls_key_package_publish_marker_key(
    server_scope: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let server = secure_key_component(server_scope, "server_scope")?;
    let actor = secure_key_component(actor_id, "actor_id")?;
    let device = secure_key_component(device_id, "device_id")?;
    Ok(format!(
        "{MLS_KEY_PACKAGE_PUBLISH_MARKER_PREFIX}.{server}.{actor}.{device}"
    ))
}

pub fn store_mls_key_package_publish_marker(
    store: &dyn SecureKeyStore,
    server_scope: &str,
    actor_id: &str,
    device_id: &str,
    key_package_id: &str,
) -> Result<(), SecureKeyStoreError> {
    let key_package = key_package_id.trim();
    if key_package.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "key_package_id is required for MLS KeyPackage publish marker".to_owned(),
        ));
    }
    let key = mls_key_package_publish_marker_key(server_scope, actor_id, device_id)?;
    store.store_secret(&key, key_package)
}

pub fn load_mls_key_package_publish_marker(
    store: &dyn SecureKeyStore,
    server_scope: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<String>, SecureKeyStoreError> {
    let key = mls_key_package_publish_marker_key(server_scope, actor_id, device_id)?;
    Ok(store
        .get_secret(&key)?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty()))
}

pub fn delete_mls_key_package_publish_marker(
    store: &dyn SecureKeyStore,
    server_scope: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<(), SecureKeyStoreError> {
    let key = mls_key_package_publish_marker_key(server_scope, actor_id, device_id)?;
    store.delete_secret(&key)
}

/// Load (without creating) the snapshot secret for `(actor, device)`.
///
/// Delegates to the account-scoped secret. `device_id` no longer scopes the
/// stored key.
pub fn load_device_snapshot_secret(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    _device_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let actor = actor_id.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_id is required for MLS snapshot secret".to_owned(),
        ));
    }
    if let Some(existing) = load_account_mls_secret(store, actor)? {
        return Ok(existing.secret);
    }
    Err(SecureKeyStoreError::NotFound)
}

/// Prepare a local account-secret rotation without mutating local state.
///
/// Each persisted MLS snapshot is decrypted with the current account secret and
/// re-encrypted with a newly-generated secret. Callers upload the returned
/// backups first, then call [`commit_account_mls_secret_rotation`] so local
/// state and the secret store advance together.
pub fn prepare_account_mls_secret_rotation(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    snapshots: &BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<AccountMlsSecretRotation, MlsRuntimeError> {
    let actor = actor_id.trim();
    if actor.is_empty() {
        return Err(MlsRuntimeError::DeviceSecret(SecureKeyStoreError::Backend(
            "actor_id is required for MLS snapshot secret".to_owned(),
        )));
    }
    let previous_secret =
        match load_account_mls_secret(store, actor).map_err(MlsRuntimeError::DeviceSecret)? {
            Some(secret) => secret,
            None => {
                let _ = load_or_create_account_mls_secret(store, actor)
                    .map_err(MlsRuntimeError::DeviceSecret)?;
                load_account_mls_secret(store, actor)
                    .map_err(MlsRuntimeError::DeviceSecret)?
                    .ok_or(MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound))?
            }
        };
    let new_version = previous_secret
        .version
        .saturating_add(1)
        .max(ACCOUNT_MLS_SECRET_CURRENT_VERSION);
    if new_version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(MlsRuntimeError::DeviceSecret(SecureKeyStoreError::Backend(
            format!("account MLS secret version {new_version} exceeds supported scan range"),
        )));
    }
    let new_secret = generate_account_mls_secret().map_err(MlsRuntimeError::DeviceSecret)?;
    let mut rewrapped_snapshots = BTreeMap::new();
    let mut failed_realms = Vec::new();
    for (realm_id, snapshot) in snapshots {
        // COR-12: one corrupt / format-drifted realm snapshot MUST NOT block the
        // rotation of every other realm (and the recovery / re-wrap flows that
        // depend on it). Record the failure and skip, mirroring the welcome-apply
        // path's "per-item failure does not abort the batch" model. The secret
        // still rotates for all decryptable realms.
        let plaintext = match crate::mls::persistence::decrypt_envelope(
            snapshot,
            &previous_secret.secret,
        ) {
            Ok(plaintext) => plaintext,
            Err(err) => {
                tracing::warn!(
                    %realm_id,
                    error = %err,
                    "skip realm during account-secret rotation: snapshot did not decrypt with previous secret"
                );
                failed_realms.push((realm_id.clone(), err.to_string()));
                continue;
            }
        };
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
        // Re-wrapping does not advance the epoch — carry the epoch-start clock
        // so a secret rotation never resets the §2.9 minimal-metadata 1h cap.
        let rotated = crate::mls::persistence::encrypt_state(
            &snapshot.realm_id,
            &snapshot.group_id,
            snapshot.epoch,
            &plaintext,
            &new_secret,
            &salt,
        )
        .carry_epoch_started_at(snapshot);
        rewrapped_snapshots.insert(realm_id.clone(), rotated);
    }
    Ok(AccountMlsSecretRotation {
        previous_version: previous_secret.version,
        new_version,
        new_secret,
        rewrapped_snapshots,
        failed_realms,
    })
}

/// Storage key for this device's HPKE X25519 private key (history sharing).
fn device_hpke_private_key_key(
    actor_id: &str,
    device_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let actor = actor_id.trim();
    let device = device_id.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_id is required for device HPKE key".to_owned(),
        ));
    }
    if device.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "device_id is required for device HPKE key".to_owned(),
        ));
    }
    Ok(format!("{DEVICE_HPKE_PRIVATE_KEY_PREFIX}.{actor}.{device}"))
}

/// Load (or first-create + persist) this device's raw 32-byte X25519 HPKE
/// private key for history sharing, returning `(private_key, public_key)` as
/// raw 32-byte vectors. The public half is advertised in a
/// `ak.realm_key.request`; the private half opens the sealed reply. Stable
/// across calls and restarts on the same device.
pub fn load_or_create_device_hpke_keypair(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    device_id: &str,
) -> Result<(Vec<u8>, Vec<u8>), SecureKeyStoreError> {
    let key = device_hpke_private_key_key(actor_id, device_id)?;
    if let Some(existing) = store.get_secret(&key)?
        && !existing.trim().is_empty()
    {
        let sk = URL_SAFE_NO_PAD
            .decode(existing.trim().as_bytes())
            .map_err(|err| {
                SecureKeyStoreError::Backend(format!("decode device HPKE private key: {err}"))
            })?;
        let pk = x25519_public_from_private(&sk)?;
        return Ok((sk, pk));
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom: {err}")))?;
    let sk = seed.to_vec();
    let pk = x25519_public_from_private(&sk)?;
    store.store_secret(&key, &URL_SAFE_NO_PAD.encode(&sk))?;
    Ok((sk, pk))
}

/// Load (without creating) this device's HPKE X25519 private key, if present.
pub fn load_device_hpke_private_key(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<Vec<u8>>, SecureKeyStoreError> {
    let key = device_hpke_private_key_key(actor_id, device_id)?;
    let Some(secret) = store.get_secret(&key)? else {
        return Ok(None);
    };
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .map(Some)
        .map_err(|err| {
            SecureKeyStoreError::Backend(format!("decode device HPKE private key: {err}"))
        })
}

/// Derive the raw 32-byte X25519 public key for a raw 32-byte private key.
fn x25519_public_from_private(private_key: &[u8]) -> Result<Vec<u8>, SecureKeyStoreError> {
    let scalar: [u8; 32] = private_key.try_into().map_err(|_| {
        SecureKeyStoreError::Backend(format!(
            "device HPKE private key must be 32 bytes, got {}",
            private_key.len()
        ))
    })?;
    let secret = x25519_dalek::StaticSecret::from(scalar);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(public.as_bytes().to_vec())
}

/// Commit a prepared rotation to local state and the secure store.
pub fn commit_account_mls_secret_rotation(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    actor_id: &str,
    rotation: &AccountMlsSecretRotation,
) -> Result<(), SecureKeyStoreError> {
    for (realm_id, envelope) in &rotation.rewrapped_snapshots {
        state_store.save_mls_snapshot(realm_id.clone(), envelope.clone());
    }
    store_account_mls_secret_version(
        secure_store,
        actor_id,
        rotation.new_version,
        &rotation.new_secret,
    )?;
    for version in 1..rotation.new_version {
        let _ = secure_store.delete_secret(&account_mls_secret_key_for_version(actor_id, version));
    }
    Ok(())
}
