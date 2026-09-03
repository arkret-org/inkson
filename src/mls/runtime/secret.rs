//! Account- and device-scoped MLS snapshot-secret management — host half.
//!
//! The secret itself, its versioned storage keys, the KeyPackage identity /
//! inventory / publish-marker keys and the local rotation preparation are
//! host-neutral and live in [`garth::mls::device_secret`]. Only the two steps
//! that need something the host owns stay here: committing a prepared rotation
//! into `LocalStateStore`, and the single-flight guard around first-time device
//! HPKE keypair creation (which needs an async lock from the host runtime).

use arkret_sdk::{AccountId, DeviceId};
pub use garth::mls::device_secret::{
    ACCOUNT_MLS_SECRET_CURRENT_VERSION, AccountMlsSecretRotation, StoredAccountMlsSecret,
    account_mls_secret_key, account_mls_secret_key_for_version, account_mls_secret_verified,
    delete_mls_key_package_identity_state, delete_mls_pairwise_key_package_publish_marker,
    ensure_account_mls_secret_durable, ensure_existing_account_mls_secret_durable,
    load_account_mls_secret, load_device_hpke_private_key, load_device_snapshot_secret,
    load_mls_key_package_identity_state, load_mls_key_package_inventory,
    load_mls_pairwise_key_package_publish_marker, load_or_create_account_mls_secret,
    mark_account_mls_secret_verified, mls_key_package_consume_request_key,
    mls_key_package_identity_state_key, mls_key_package_inventory_key,
    mls_pairwise_key_package_publish_marker_key, prepare_account_mls_secret_rotation,
    replace_account_mls_secret_version, store_account_mls_secret,
    store_mls_key_package_identity_state, store_mls_key_package_identity_state_durable,
    store_mls_key_package_inventory, store_mls_pairwise_key_package_publish_marker,
};
use garth::mls::device_secret::{
    create_device_hpke_keypair_durable, load_device_hpke_keypair, store_account_mls_secret_version,
};

use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError};

/// Load or create the device HPKE keypair and await the private-key commit.
/// Network requests that advertise the public half must use this entry point.
///
/// The single-flight lock is the host's: two concurrent first-time callers must
/// not both mint material, or the loser advertises a public key whose private
/// half was overwritten. garth binds no async runtime, so it exposes the load
/// and the create halves and this composition holds the lock.
pub async fn load_or_create_device_hpke_keypair_durable(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<(Vec<u8>, Vec<u8>), SecureKeyStoreError> {
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
    for (realm_id, envelope) in &rotation.rewrapped_snapshots {
        state_store
            .save_mls_snapshot(realm_id.clone(), envelope.clone())
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
