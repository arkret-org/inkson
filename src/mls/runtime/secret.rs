//! Account- and device-scoped MLS checkpoint-secret management.
//!
//! The checkpoint secret is account-scoped and shared by every device of the
//! account; it is recoverable through the user's recovery material. The
//! `prepare_*` rotation helper produces new wrapping material without mutating
//! local state so a caller can upload the server-side backups before
//! committing.
//!
//! None of this is protocol surface: every key here addresses a device-local
//! secret slot, and nothing in this module crosses the wire.

use std::collections::BTreeMap;

use arkret_sdk::{AccountId, DeviceId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use garth::{account_id_storage_digest, device_storage_digest};

use super::MlsRuntimeError;
use crate::mls::persistence::{self, MlsLocalCheckpointEnvelope};
use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError};

// Secret-store key prefixes. These are at-rest addresses, not names: every
// secret already written by a shipped client lives under them, so renaming one
// would orphan the stored secret and read as "device has no MLS material".
const ACCOUNT_MLS_SECRET_PREFIX: &str = "inkson.mls_snapshot.account_secret";
const ACCOUNT_MLS_SECRET_VERIFIED_MARKER: &str = "verified";
pub const ACCOUNT_MLS_SECRET_CURRENT_VERSION: u32 = 1;
const ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION: u32 = 32;
const MLS_KEY_PACKAGE_IDENTITY_STATE_PREFIX: &str = "inkson.mls_key_package.identity_state.v1";
const MLS_KEY_PACKAGE_CONSUME_REQUEST_PREFIX: &str = "inkson.mls_key_package.consume_request.v1";
const MLS_KEY_PACKAGE_INVENTORY_PREFIX: &str = "inkson.mls_key_package.inventory.v1";
/// Per-(account authority, device) X25519 keypair this device advertises so a
/// peer can seal material addressed to exactly this device.
///
/// The receiver would ideally open with the X25519 init-key private half of its
/// published MLS KeyPackage, but OpenMLS does not surface that raw private
/// scalar through the SDK, so a dedicated persisted device keypair is minted
/// instead.
const DEVICE_HPKE_PRIVATE_KEY_PREFIX: &str = "inkson.device_hpke_x25519.private.v1";

/// Stored account-scoped MLS checkpoint secret plus the local key version that
/// carried it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAccountMlsSecret {
    pub version: u32,
    pub secret: String,
}

/// Local account-scoped secret rotation material. The upload path wraps the new
/// account-secret backup with `new_secret`, then commits this material locally
/// once the server-side backups have landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMlsSecretRotation {
    pub previous_version: u32,
    pub new_version: u32,
    pub new_secret: String,
    pub rewrapped_checkpoints: BTreeMap<String, MlsLocalCheckpointEnvelope>,
    /// Realms whose checkpoint could not be decrypted with the previous secret
    /// and were therefore skipped instead of aborting the whole rotation, as
    /// `(realm_id, error)` pairs. Empty on a clean rotation.
    pub failed_realms: Vec<(String, String)>,
}

/// Account-scoped storage key for a specific MLS checkpoint-secret version.
pub fn account_mls_secret_key_for_version(
    authority: &AccountId,
    version: u32,
) -> Result<String, SecureKeyStoreError> {
    let authority_digest = account_id_storage_digest(authority)?;
    Ok(format!(
        "{ACCOUNT_MLS_SECRET_PREFIX}.v{version}.{authority_digest}"
    ))
}

/// Default write key for the account-scoped MLS checkpoint secret shared by
/// every device of the account.
pub fn account_mls_secret_key(authority: &AccountId) -> Result<String, SecureKeyStoreError> {
    account_mls_secret_key_for_version(authority, ACCOUNT_MLS_SECRET_CURRENT_VERSION)
}

fn validate_account_secret(secret: &str) -> Result<(), SecureKeyStoreError> {
    if secret.trim().is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "account MLS secret must not be empty".to_owned(),
        ));
    }
    Ok(())
}

/// Store (or overwrite) a specific version of the account-scoped secret.
pub fn store_account_mls_secret_version(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    version: u32,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    if version == 0 || version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(SecureKeyStoreError::Backend(format!(
            "account MLS secret version {version} is outside the supported scan range"
        )));
    }
    validate_account_secret(secret)?;
    store.store_secret(
        &account_mls_secret_key_for_version(authority, version)?,
        secret,
    )
}

/// Replace every locally known account MLS secret version with one recovered
/// from the account backup.
///
/// Recovery must win over a stale local secret left by a previous incomplete
/// bootstrap: [`load_account_mls_secret`] picks the highest version, so keeping
/// a newer-but-wrong local version would make the recovered backup ineffective.
pub fn replace_account_mls_secret_version(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    version: u32,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    if version == 0 || version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(SecureKeyStoreError::Backend(format!(
            "account MLS secret version {version} is outside the supported scan range"
        )));
    }
    validate_account_secret(secret)?;
    store.store_secret(
        &account_mls_secret_key_for_version(authority, version)?,
        secret,
    )?;
    for existing_version in 1..=ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        if existing_version != version {
            store.delete_secret(&account_mls_secret_key_for_version(
                authority,
                existing_version,
            )?)?;
        }
    }
    Ok(())
}

/// Store (or overwrite) the current account-scoped MLS checkpoint secret.
pub fn store_account_mls_secret(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    store_account_mls_secret_version(store, authority, ACCOUNT_MLS_SECRET_CURRENT_VERSION, secret)
}

/// Load the highest local account-secret version currently present.
pub fn load_account_mls_secret(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<Option<StoredAccountMlsSecret>, SecureKeyStoreError> {
    for version in (1..=ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION).rev() {
        let key = account_mls_secret_key_for_version(authority, version)?;
        if let Some(secret) = store.get_secret(&key)?
            && !secret.trim().is_empty()
        {
            return Ok(Some(StoredAccountMlsSecret { version, secret }));
        }
    }
    Ok(None)
}

fn account_mls_secret_verified_key(authority: &AccountId) -> Result<String, SecureKeyStoreError> {
    let authority_digest = account_id_storage_digest(authority)?;
    Ok(format!(
        "{ACCOUNT_MLS_SECRET_PREFIX}.{ACCOUNT_MLS_SECRET_VERIFIED_MARKER}.v1.{authority_digest}"
    ))
}

/// Mark the active account secret as proven to belong to the account's recovery
/// chain. Only a successful backup upload or recovery import may set this.
pub fn mark_account_mls_secret_verified(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<(), SecureKeyStoreError> {
    store.store_secret(&account_mls_secret_verified_key(authority)?, "verified")
}

/// Whether this device has proved that its local account secret belongs to the
/// account's recovery chain. A freshly generated bootstrap secret is false.
pub fn account_mls_secret_verified(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<bool, SecureKeyStoreError> {
    Ok(store
        .get_secret(&account_mls_secret_verified_key(authority)?)?
        .as_deref()
        == Some("verified"))
}

fn generate_account_mls_secret() -> Result<String, SecureKeyStoreError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom: {err}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Load (or create) the account-scoped MLS checkpoint secret: the highest
/// existing versioned secret, else a freshly generated 32-byte value stored
/// under the current account key.
pub fn load_or_create_account_mls_secret(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<String, SecureKeyStoreError> {
    if let Some(existing) = load_account_mls_secret(store, authority)? {
        return Ok(existing.secret);
    }
    let secret = generate_account_mls_secret()?;
    store_account_mls_secret(store, authority, &secret)?;
    Ok(secret)
}

/// Load-or-create the account MLS secret and await its durable persistence.
///
/// [`load_or_create_account_mls_secret`] writes through the synchronous store
/// surface; on wasm the IndexedDB commit behind that write is a detached
/// background task that a page unload silently drops. State persisted under
/// this secret goes through the durable-awaiting writer, so the secret could
/// reach disk after the checkpoint it wraps, or never. A reload in that window
/// leaves a checkpoint no local secret can open, which reads as "no account MLS
/// secret" and dead-locks every later encrypted write on this device. Callers
/// that are about to persist secret-wrapped state must use this variant.
pub async fn ensure_account_mls_secret_durable(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<String, SecureKeyStoreError> {
    if let Some(existing) = load_account_mls_secret(store, authority)? {
        // Re-commit the already-visible value: if the creation-time background
        // write was lost to an unload, this is the retry that lands it.
        store
            .store_secret_durable(
                &account_mls_secret_key_for_version(authority, existing.version)?,
                &existing.secret,
            )
            .await?;
        return Ok(existing.secret);
    }
    let secret = generate_account_mls_secret()?;
    store
        .store_secret_durable(&account_mls_secret_key(authority)?, &secret)
        .await?;
    // Concurrent first-creation is last-write-wins on the store; re-read so
    // every caller converges on the value that actually landed.
    if let Some(landed) = load_account_mls_secret(store, authority)? {
        return Ok(landed.secret);
    }
    Ok(secret)
}

/// Re-commit an existing account MLS secret durably without creating one.
///
/// Returning devices and Welcome recipients must recover the account recovery
/// unit when the secret is absent. Minting here would create a second wrapping
/// root that cannot open the account's existing checkpoints or backups.
pub async fn ensure_existing_account_mls_secret_durable(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<String, SecureKeyStoreError> {
    let existing =
        load_account_mls_secret(store, authority)?.ok_or(SecureKeyStoreError::NotFound)?;
    store
        .store_secret_durable(
            &account_mls_secret_key_for_version(authority, existing.version)?,
            &existing.secret,
        )
        .await?;
    Ok(existing.secret)
}

pub fn mls_key_package_identity_state_key(
    authority: &AccountId,
    device_id: &DeviceId,
    key_package_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let key_package = key_package_id.trim();
    if key_package.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "key_package_id is required for MLS KeyPackage identity state".to_owned(),
        ));
    }
    let scope = account_device_storage_suffix(authority, device_id)?;
    let key_package = secure_key_component(key_package, "key_package_id")?;
    Ok(format!(
        "{MLS_KEY_PACKAGE_IDENTITY_STATE_PREFIX}.{scope}.{key_package}"
    ))
}

/// Durable exact-replay slot for one KeyPackage claim's signed consume body.
///
/// The service's idempotency key is `claim_id`: once a consume body has been
/// accepted, changing even `durable_at` makes a later delivery a conflicting
/// request. Keep the first signed body scoped to the exact account and device
/// so a redelivered Welcome can resend identical canonical bytes after restart.
pub fn mls_key_package_consume_request_key(
    authority: &AccountId,
    device_id: &DeviceId,
    claim_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let scope = account_device_storage_suffix(authority, device_id)?;
    let claim = secure_key_component(claim_id, "claim_id")?;
    Ok(format!(
        "{MLS_KEY_PACKAGE_CONSUME_REQUEST_PREFIX}.{scope}.{claim}"
    ))
}

/// Non-durable KeyPackage identity-state write.
///
/// Production writes go through [`store_mls_key_package_identity_state_durable`]:
/// publishing a KeyPackage whose private identity state is not yet committed
/// strands the claimer. This synchronous form exists for test fixtures that
/// seed the store outside an async context.
pub fn store_mls_key_package_identity_state(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    key_package_id: &str,
    serialized_state: &[u8],
) -> Result<(), SecureKeyStoreError> {
    if serialized_state.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "MLS KeyPackage identity state must not be empty".to_owned(),
        ));
    }
    let key = mls_key_package_identity_state_key(authority, device_id, key_package_id)?;
    store.store_secret(&key, &URL_SAFE_NO_PAD.encode(serialized_state))
}

/// Durable variant of the KeyPackage identity-state write. Production must use
/// this one: a published KeyPackage whose private identity state is not yet
/// committed strands the claimer.
pub async fn store_mls_key_package_identity_state_durable(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    key_package_id: &str,
    serialized_state: &[u8],
) -> Result<(), SecureKeyStoreError> {
    if serialized_state.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "MLS KeyPackage identity state must not be empty".to_owned(),
        ));
    }
    let key = mls_key_package_identity_state_key(authority, device_id, key_package_id)?;
    store
        .store_secret_durable(&key, &URL_SAFE_NO_PAD.encode(serialized_state))
        .await
}

pub fn load_mls_key_package_identity_state(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    key_package_id: &str,
) -> Result<Option<Vec<u8>>, SecureKeyStoreError> {
    let key = mls_key_package_identity_state_key(authority, device_id, key_package_id)?;
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
            SecureKeyStoreError::Backend(format!("decode MLS KeyPackage identity state: {err}"))
        })
}

pub fn delete_mls_key_package_identity_state(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    key_package_id: &str,
) -> Result<(), SecureKeyStoreError> {
    let key = mls_key_package_identity_state_key(authority, device_id, key_package_id)?;
    store.delete_secret(&key)
}

fn secure_key_component(value: &str, label: &str) -> Result<String, SecureKeyStoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SecureKeyStoreError::Backend(format!(
            "{label} is required for the MLS KeyPackage storage key"
        )));
    }
    Ok(URL_SAFE_NO_PAD.encode(trimmed.as_bytes()))
}

fn account_device_storage_suffix(
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<String, SecureKeyStoreError> {
    let authority = account_id_storage_digest(authority)?;
    let device = device_storage_digest(device_id);
    Ok(format!("{authority}.{device}"))
}

pub fn mls_key_package_inventory_key(
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<String, SecureKeyStoreError> {
    let scope = account_device_storage_suffix(authority, device_id)?;
    Ok(format!("{MLS_KEY_PACKAGE_INVENTORY_PREFIX}.{scope}"))
}

pub fn store_mls_key_package_inventory(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    inventory: &arkret_sdk::LocalMlsKeyPackageInventory,
) -> Result<(), SecureKeyStoreError> {
    let key = mls_key_package_inventory_key(authority, device_id)?;
    let encoded = serde_json::to_string(inventory)
        .map_err(|error| SecureKeyStoreError::Backend(error.to_string()))?;
    store.store_secret(&key, &encoded)
}

pub fn load_mls_key_package_inventory(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<arkret_sdk::LocalMlsKeyPackageInventory, SecureKeyStoreError> {
    let key = mls_key_package_inventory_key(authority, device_id)?;
    let expected = arkret_sdk::MlsEndpointIdentity::human_device(
        authority.principal_id.clone(),
        device_id.clone(),
    );
    let Some(encoded) = store.get_secret(&key)? else {
        return Ok(arkret_sdk::LocalMlsKeyPackageInventory {
            endpoint: expected,
            entries: BTreeMap::new(),
        });
    };
    let inventory: arkret_sdk::LocalMlsKeyPackageInventory = serde_json::from_str(&encoded)
        .map_err(|error| SecureKeyStoreError::Backend(format!("invalid MLS inventory: {error}")))?;
    if inventory.endpoint != expected {
        return Err(SecureKeyStoreError::Backend(
            "MLS inventory endpoint does not match the active authority and device".to_owned(),
        ));
    }
    Ok(inventory)
}

/// Load (without creating) the checkpoint secret for an account authority.
///
/// Delegates to the account-scoped secret; `device_id` does not scope the key.
pub fn load_device_checkpoint_secret(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    _device_id: &DeviceId,
) -> Result<String, SecureKeyStoreError> {
    match load_account_mls_secret(store, authority)? {
        Some(existing) => Ok(existing.secret),
        None => Err(SecureKeyStoreError::NotFound),
    }
}

/// Prepare a local account-secret rotation without mutating local state.
///
/// Each persisted MLS checkpoint is decrypted with the current account secret
/// and re-encrypted with a newly generated one. Callers upload the resulting
/// backups first, then call
/// [`crate::mls::runtime::commit_account_mls_secret_rotation`] so local state
/// and the secret store advance together.
pub fn prepare_account_mls_secret_rotation(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    checkpoints: &BTreeMap<String, MlsLocalCheckpointEnvelope>,
) -> Result<AccountMlsSecretRotation, MlsRuntimeError> {
    let previous_secret = load_account_mls_secret(store, authority)
        .map_err(MlsRuntimeError::DeviceSecret)?
        .ok_or(MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound))?;
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
    let mut rewrapped_checkpoints = BTreeMap::new();
    let mut failed_realms = Vec::new();
    for (realm_id, checkpoint) in checkpoints {
        // One corrupt or format-drifted Realm checkpoint MUST NOT block the
        // rotation of every other Realm (and the recovery / re-wrap flows that
        // depend on it). Record the failure and skip; the secret still rotates
        // for every decryptable Realm.
        let plaintext = match persistence::decrypt_envelope(checkpoint, &previous_secret.secret) {
            Ok(plaintext) => plaintext,
            Err(err) => {
                tracing::warn!(
                    %realm_id,
                    error = %err,
                    "skip realm during account-secret rotation: checkpoint did not decrypt with the previous secret"
                );
                failed_realms.push((realm_id.clone(), err.to_string()));
                continue;
            }
        };
        let mut salt = [0_u8; 16];
        getrandom::fill(&mut salt).map_err(|err| {
            MlsRuntimeError::DeviceSecret(SecureKeyStoreError::Backend(format!("getrandom: {err}")))
        })?;
        // Re-wrapping does not advance the epoch: carry the epoch-start clock
        // so a secret rotation never resets the minimal-metadata epoch-age cap.
        let rotated = persistence::encrypt_state(
            &checkpoint.realm_id,
            &checkpoint.group_id,
            checkpoint.epoch,
            &plaintext,
            &new_secret,
            &salt,
        )
        .carry_epoch_started_at(checkpoint);
        rewrapped_checkpoints.insert(realm_id.clone(), rotated);
    }
    Ok(AccountMlsSecretRotation {
        previous_version: previous_secret.version,
        new_version,
        new_secret,
        rewrapped_checkpoints,
        failed_realms,
    })
}

/// Storage key for this device's HPKE X25519 private key.
fn device_hpke_private_key_key(
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<String, SecureKeyStoreError> {
    let scope = account_device_storage_suffix(authority, device_id)?;
    Ok(format!("{DEVICE_HPKE_PRIVATE_KEY_PREFIX}.{scope}"))
}

/// A raw X25519 keypair as `(private, public)` bytes.
pub type DeviceHpkeKeypair = (Vec<u8>, Vec<u8>);

/// Generate this device's HPKE X25519 keypair and await the private-key commit.
///
/// Unconditional: it always mints and stores fresh material.
/// [`load_or_create_device_hpke_keypair_durable`] composes it with
/// [`load_device_hpke_keypair`] under a single-flight guard. Advertising the
/// public half before the private half is durable would strand a peer's
/// ciphertext, so the durable write is awaited here.
pub async fn create_device_hpke_keypair_durable(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<DeviceHpkeKeypair, SecureKeyStoreError> {
    let key = device_hpke_private_key_key(authority, device_id)?;
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|error| SecureKeyStoreError::Backend(format!("getrandom: {error}")))?;
    let private_key = seed.to_vec();
    let public_key = x25519_public_from_private(&private_key)?;
    store
        .store_secret_durable(&key, &URL_SAFE_NO_PAD.encode(&private_key))
        .await?;
    Ok((private_key, public_key))
}

/// The stored device HPKE keypair, when this device already has one.
pub fn load_device_hpke_keypair(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<Option<DeviceHpkeKeypair>, SecureKeyStoreError> {
    let Some(private_key) = load_device_hpke_private_key(store, authority, device_id)? else {
        return Ok(None);
    };
    let public_key = x25519_public_from_private(&private_key)?;
    Ok(Some((private_key, public_key)))
}

/// Load (without creating) this device's HPKE X25519 private key, if present.
pub fn load_device_hpke_private_key(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<Option<Vec<u8>>, SecureKeyStoreError> {
    let key = device_hpke_private_key_key(authority, device_id)?;
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
pub fn x25519_public_from_private(private_key: &[u8]) -> Result<Vec<u8>, SecureKeyStoreError> {
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

/// Load or create the device HPKE keypair and await the private-key commit.
/// Network requests that advertise the public half must use this entry point.
///
/// The single-flight lock is the host's: two concurrent first-time callers must
/// not both mint material, or the loser advertises a public key whose private
/// half was overwritten.
pub async fn load_or_create_device_hpke_keypair_durable(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<DeviceHpkeKeypair, SecureKeyStoreError> {
    static HPKE_KEY_CREATE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
        std::sync::OnceLock::new();
    let _guard = HPKE_KEY_CREATE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    if let Some(existing) = load_device_hpke_keypair(store, authority, device_id)? {
        return Ok(existing);
    }
    create_device_hpke_keypair_durable(store, authority, device_id).await
}

/// Commit a prepared rotation to local state and the secure store.
pub fn commit_account_mls_secret_rotation(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    authority: &AccountId,
    rotation: &AccountMlsSecretRotation,
) -> Result<(), SecureKeyStoreError> {
    for (realm_id, envelope) in &rotation.rewrapped_checkpoints {
        state_store
            .save_mls_checkpoint(realm_id.clone(), envelope.clone())
            .map_err(SecureKeyStoreError::Backend)?;
    }
    store_account_mls_secret_version(
        secure_store,
        authority,
        rotation.new_version,
        &rotation.new_secret,
    )?;
    for version in 1..rotation.new_version {
        let key = account_mls_secret_key_for_version(authority, version)?;
        let _ = secure_store.delete_secret(&key);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{Did, DidCoreId, project_did_to_core_id};

    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;

    fn authority(principal_did: &str, server_id: &str) -> AccountId {
        let did = Did::new(principal_did).unwrap();
        AccountId::new(
            DidCoreId::from(project_did_to_core_id(&did).unwrap()),
            DidCoreId::new(server_id).unwrap(),
        )
    }

    fn device(number: u8) -> DeviceId {
        DeviceId::new(format!("ak:device:01904100-0000-7000-8000-{number:012}")).unwrap()
    }

    #[test]
    fn account_secret_is_reused_within_exact_authority() {
        let store = MemorySecureKeyStore::new();
        let authority = authority(
            "did:webvh:z6mkalice:old.example:alice",
            "ak:did_core:web:server.example",
        );
        let first = load_or_create_account_mls_secret(&store, &authority).unwrap();
        let second = load_or_create_account_mls_secret(&store, &authority).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 43);
    }

    #[test]
    fn checkpoint_secret_load_does_not_create() {
        let store = MemorySecureKeyStore::new();
        let authority = authority(
            "did:webvh:z6mkalice:alice.example",
            "ak:did_core:web:server.example",
        );
        let missing = load_device_checkpoint_secret(&store, &authority, &device(1)).unwrap_err();
        assert!(matches!(missing, SecureKeyStoreError::NotFound));
        assert!(store.list_secret_keys(None).unwrap().is_empty());
    }

    #[test]
    fn same_core_relocation_keeps_the_account_secret_key() {
        let old_authority = authority(
            "did:webvh:z6mkalice:old.example:alice",
            "ak:did_core:web:server.example",
        );
        let relocated_authority = authority(
            "did:webvh:z6mkalice:new.example:users:alice",
            "ak:did_core:web:server.example",
        );
        assert_eq!(old_authority, relocated_authority);
        assert_eq!(
            account_mls_secret_key(&old_authority).unwrap(),
            account_mls_secret_key(&relocated_authority).unwrap()
        );
    }

    #[test]
    fn same_principal_on_different_servers_has_distinct_secrets() {
        let store = MemorySecureKeyStore::new();
        let first = authority(
            "did:webvh:z6mkalice:alice.example",
            "ak:did_core:web:server-a.example",
        );
        let second = authority(
            "did:webvh:z6mkalice:alice.example",
            "ak:did_core:web:server-b.example",
        );
        store_account_mls_secret(&store, &first, "server-a-secret").unwrap();
        store_account_mls_secret(&store, &second, "server-b-secret").unwrap();

        assert_eq!(
            load_account_mls_secret(&store, &first)
                .unwrap()
                .unwrap()
                .secret,
            "server-a-secret"
        );
        assert_eq!(
            load_account_mls_secret(&store, &second)
                .unwrap()
                .unwrap()
                .secret,
            "server-b-secret"
        );
        assert_ne!(
            account_mls_secret_key(&first).unwrap(),
            account_mls_secret_key(&second).unwrap()
        );
    }

    #[test]
    fn account_secret_is_shared_across_devices_but_keypackage_state_is_not() {
        let store = MemorySecureKeyStore::new();
        let authority = authority(
            "did:webvh:z6mkalice:alice.example",
            "ak:did_core:web:server.example",
        );
        let first_device = device(1);
        let second_device = device(2);
        store_account_mls_secret(&store, &authority, "shared-secret").unwrap();
        assert_eq!(
            load_device_checkpoint_secret(&store, &authority, &first_device).unwrap(),
            load_device_checkpoint_secret(&store, &authority, &second_device).unwrap()
        );

        assert_ne!(
            mls_key_package_identity_state_key(&authority, &first_device, "ak:keypackage:one")
                .unwrap(),
            mls_key_package_identity_state_key(&authority, &second_device, "ak:keypackage:one")
                .unwrap()
        );
    }

    #[test]
    fn keypackage_inventory_is_v1_and_authority_device_scoped() {
        let first_authority = authority(
            "did:webvh:z6mkalice:alice.example",
            "ak:did_core:web:server-a.example",
        );
        let second_authority = authority(
            "did:webvh:z6mkalice:alice.example",
            "ak:did_core:web:server-b.example",
        );
        let first_device = device(1);
        let second_device = device(2);
        let key = mls_key_package_inventory_key(&first_authority, &first_device).unwrap();
        assert!(key.starts_with("inkson.mls_key_package.inventory.v1."));
        assert_ne!(
            key,
            mls_key_package_inventory_key(&second_authority, &first_device).unwrap()
        );
        assert_ne!(
            key,
            mls_key_package_inventory_key(&first_authority, &second_device).unwrap()
        );
    }

    #[test]
    fn recovered_version_replaces_stale_higher_versions_only_in_its_authority() {
        let store = MemorySecureKeyStore::new();
        let first = authority(
            "did:webvh:z6mkalice:alice.example",
            "ak:did_core:web:server-a.example",
        );
        let second = authority(
            "did:webvh:z6mkalice:alice.example",
            "ak:did_core:web:server-b.example",
        );
        store_account_mls_secret_version(&store, &first, 3, "stale").unwrap();
        store_account_mls_secret_version(&store, &second, 3, "other-server").unwrap();
        replace_account_mls_secret_version(&store, &first, 2, "recovered").unwrap();

        assert_eq!(
            load_account_mls_secret(&store, &first)
                .unwrap()
                .unwrap()
                .secret,
            "recovered"
        );
        assert_eq!(
            load_account_mls_secret(&store, &second)
                .unwrap()
                .unwrap()
                .secret,
            "other-server"
        );
    }

    #[test]
    fn a_rotation_skips_an_undecryptable_realm_and_rewraps_the_rest() {
        let store = MemorySecureKeyStore::new();
        let authority = authority(
            "did:webvh:z6mkalice:alice.example",
            "ak:did_core:web:server.example",
        );
        store_account_mls_secret(&store, &authority, "old-secret").unwrap();
        let good = persistence::encrypt_state(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            "group-a",
            4,
            b"state",
            "old-secret",
            b"salt",
        );
        let foreign = persistence::encrypt_state(
            "ak:realm:Afa-XWDzmMaAI5o0i4JEB845_F-vdio4zG-xF_FzJHK1",
            "group-b",
            2,
            b"state",
            "another-secret",
            b"salt",
        );
        let checkpoints = BTreeMap::from([
            ("realm-a".to_owned(), good.clone()),
            ("realm-b".to_owned(), foreign),
        ]);
        let rotation = prepare_account_mls_secret_rotation(&store, &authority, &checkpoints)
            .expect("rotation prepares");
        assert_eq!(rotation.previous_version, 1);
        assert_eq!(rotation.new_version, 2);
        assert_eq!(rotation.rewrapped_checkpoints.len(), 1);
        assert_eq!(
            rotation
                .failed_realms
                .iter()
                .map(|(realm, _)| realm.as_str())
                .collect::<Vec<_>>(),
            ["realm-b"]
        );
        let rotated = &rotation.rewrapped_checkpoints["realm-a"];
        assert_eq!(rotated.epoch, good.epoch);
        assert_eq!(rotated.epoch_started_at, good.epoch_started_at);
        assert_eq!(
            persistence::decrypt_envelope(rotated, &rotation.new_secret).unwrap(),
            b"state".to_vec()
        );
    }
}
