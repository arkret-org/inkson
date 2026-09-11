//! Pure functions and small data types for post-login / startup-check effects.
//!
//! mechanically moved from `app.rs`; move-only, with no changes to
//! logic, signatures, or canonical bytes.
//! This module groups three concerns:
//!   - session refresh feasibility checks (`has_bootstrap_refresh_material`, etc.);
//!   - device authorization state projections (`*_device_authorization_*`);
//!   - MLS backup/unlock dual checks and device-message Welcome bootstrap
//!     (`mls_recovery_setup_missing` / `mls_welcome_bootstrap_key` /
//!     `bootstrap_mls_welcome_for_realm`).
//!
//! `app.rs` re-exports with `pub(crate) use bootstrap::*;`, preserving existing
//! call sites and `app_tests.rs` `use super::*` resolution paths.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use arkret_wire::event_kind_str;
use dioxus::prelude::Signal;
use garth::mls::welcome_admission::{
    device_authorization_from_record, device_revoked, mls_welcome_batch_is_exclusively_for_realm,
    recovery_public_key_secret_storage_backup_present, recovery_setup_prompt_required,
    retain_mls_welcomes_for_realm,
};
use serde_json::Value;

use super::server_key;
use crate::state::LocalStateStore;

pub(crate) const RECOVERY_AUTO_PROMPT_SHOWN_KEY: &str = "recovery.auto_prompt_shown.v1";
pub(crate) const RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY: &str =
    "recovery.auto_prompt_local_only_shown.v1";
/// Per-account flag: the recommended-encryption-floor health check has been
/// auto-acknowledged. The underlying `floor_low` condition stays true until the
/// account actually ratchets a Realm to the recommended floor, so without this
/// flag the auto-apply effect would re-run on every render/navigation.
/// Mirrors `RECOVERY_AUTO_PROMPT_SHOWN_KEY`: run at most once per account, then
/// leave the user to manage it from settings.
pub(crate) const ENCRYPTION_FLOOR_PROMPT_DISMISSED_KEY: &str =
    "encryption.floor_prompt_dismissed.v1";

pub(crate) fn has_bootstrap_refresh_material(
    store: &LocalStateStore,
    active_account: Option<&crate::config::ActiveAccountContext>,
) -> bool {
    let Some(account) = active_account else {
        return false;
    };
    let state = store.load();
    state.session_grant.as_ref().is_some_and(|grant| {
        crate::identity::session_refresh::grant_matches_station(grant, account.server_url.as_str())
            && crate::identity::session_refresh::grant_matches_principal_id(
                grant,
                account.principal_id(),
            )
            && grant.device_id == account.device_id
            && grant.audience_id == account.authority.station_id
            && !crate::identity::session_refresh::grant_is_dead(grant)
    })
}

pub(crate) fn local_state_has_encrypted_realm(state_store: &LocalStateStore) -> bool {
    state_store
        .load()
        .realm_tree_projections
        .values()
        .any(garth::realm_projection_is_encrypted)
}

pub(crate) fn local_mls_epoch_floor_all(state_store: &LocalStateStore) -> u64 {
    let mut max_epoch = 0_u64;
    for (realm_id, snapshot) in state_store.mls_local_checkpoints() {
        max_epoch = max_epoch.max(snapshot.epoch);
        max_epoch = max_epoch.max(
            state_store
                .seal_view_for_realm(&realm_id)
                .mls_epoch
                .unwrap_or(0),
        );
    }
    for seal_view in state_store.seal_views().values() {
        max_epoch = max_epoch.max(seal_view.mls_epoch.unwrap_or(0));
    }
    max_epoch
}

pub(crate) fn recovery_setup_prompt_required_for_local_state(
    account_recovery_configured: Option<bool>,
    local_recovery_configured: bool,
) -> bool {
    recovery_setup_prompt_required(account_recovery_configured) && !local_recovery_configured
}

pub(crate) fn recovery_setup_prompt_required_for_account_state(
    account_recovery_configured: Option<bool>,
    local_recovery_configured: bool,
    account_has_other_active_devices: bool,
) -> bool {
    recovery_setup_prompt_required_for_local_state(
        account_recovery_configured,
        local_recovery_configured,
    ) && !account_has_other_active_devices
}

pub(crate) fn recovery_auto_prompt_pending_local_only_fingerprint(
    store: &LocalStateStore,
    account_recovery_configured: Option<bool>,
) -> Option<String> {
    if !matches!(account_recovery_configured, Some(false)) {
        return None;
    }
    let fingerprint = crate::views::recovery::local_recovery_key_fingerprint(store)?;
    let prompted_fingerprint = store
        .load_plain_local_data(RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if prompted_fingerprint.as_deref() == Some(fingerprint.as_str()) {
        return None;
    }
    Some(fingerprint)
}

pub(crate) fn recovery_auto_prompt_already_prompted(
    store: &LocalStateStore,
    account_recovery_configured: Option<bool>,
) -> bool {
    if recovery_auto_prompt_pending_local_only_fingerprint(store, account_recovery_configured)
        .is_some()
    {
        return false;
    }
    store
        .load_plain_local_data(RECOVERY_AUTO_PROMPT_SHOWN_KEY)
        .is_some()
}

/// Whether the recommended-encryption-floor check was already auto-acknowledged
/// for this account (see [`ENCRYPTION_FLOOR_PROMPT_DISMISSED_KEY`]).
pub(crate) fn encryption_floor_prompt_acknowledged(store: &LocalStateStore) -> bool {
    store
        .load_plain_local_data(ENCRYPTION_FLOOR_PROMPT_DISMISSED_KEY)
        .is_some()
}

pub(crate) fn current_device_authorization_from_account_viewer(
    viewer: &Value,
    configured_device_id: &str,
) -> Option<bool> {
    let configured_device = configured_device_id.trim();
    let devices = viewer.get("devices").and_then(Value::as_array)?;
    if devices.is_empty() {
        return None;
    }

    let current_row = (!configured_device.is_empty()).then(|| {
        devices.iter().find(|device| {
            device
                .get("device_id")
                .and_then(Value::as_str)
                .map(str::trim)
                == Some(configured_device)
        })
    })?;

    match current_row {
        Some(device) => device_authorization_from_record(device),
        None => Some(false),
    }
}

pub(crate) fn account_has_other_active_devices_from_account_viewer(
    viewer: &Value,
    configured_device_id: &str,
) -> bool {
    let current_device = configured_device_id.trim();
    viewer
        .get("devices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|device| {
            device
                .get("device_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .is_some_and(|device_id| !device_id.is_empty() && device_id != current_device)
                && !device_revoked(device)
        })
}

pub(crate) fn device_authorization_required_from_account_viewer(
    viewer: &Value,
    configured_device_id: &str,
) -> bool {
    !matches!(
        current_device_authorization_from_account_viewer(viewer, configured_device_id),
        Some(true)
    )
}

fn recovery_key_path_configured_for_mls_setup(
    list_payload: &Value,
    state_store: &LocalStateStore,
    account_recovery_configured: Option<bool>,
) -> bool {
    if matches!(account_recovery_configured, Some(true)) {
        return true;
    }
    if !recovery_public_key_secret_storage_backup_present(list_payload) {
        return false;
    }
    crate::views::recovery::local_recovery_key_fingerprint(state_store).is_some()
        || crate::views::recovery::local_recovery_public_key(state_store).is_some()
}

pub(crate) fn mls_recovery_setup_missing(
    list_payload: &Value,
    state_store: &LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    account_recovery_configured: Option<bool>,
) -> bool {
    if crate::mls::account_recovery::select_preferred_mls_account_secret_backup(list_payload)
        .is_some()
        || crate::mls::account_recovery::select_mls_account_secret_backup(list_payload).is_some()
    {
        return false;
    }
    if matches!(
        crate::mls::runtime::load_account_mls_secret(secure_store, authority),
        Ok(Some(_))
    ) {
        return false;
    }
    if recovery_key_path_configured_for_mls_setup(
        list_payload,
        state_store,
        account_recovery_configured,
    ) {
        return false;
    }
    local_state_has_encrypted_realm(state_store)
        || !crate::mls::account_recovery::select_mls_history_backups(list_payload).is_empty()
}

pub(crate) fn mls_welcome_bootstrap_key(
    server_url: &url::Url,
    session_credential: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    realm_id: &arkret_sdk::RealmId,
    e2ee_ready: bool,
    sync_bootstrap_complete: bool,
) -> Option<String> {
    if !e2ee_ready || !sync_bootstrap_complete {
        return None;
    }
    let base = server_key(server_url.as_str());
    let session = session_credential.trim();
    let principal = authority.principal_id.as_str();
    let station = authority.station_id.as_str();
    let device = device_id.as_str();
    let realm = realm_id.as_str();
    if base.is_empty()
        || session.is_empty()
        || principal.is_empty()
        || station.is_empty()
        || device.is_empty()
        || realm.is_empty()
    {
        return None;
    }

    let mut token_hash = DefaultHasher::new();
    session.hash(&mut token_hash);
    Some(format!(
        "{base}|{principal}|{station}|{device}|{realm}|{:016x}",
        token_hash.finish()
    ))
}

pub(crate) fn mls_key_package_publish_key(
    server_url: &url::Url,
    session_credential: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    e2ee_ready: bool,
    sync_bootstrap_complete: bool,
) -> Option<String> {
    if !e2ee_ready || !sync_bootstrap_complete {
        return None;
    }
    let base = server_key(server_url.as_str());
    let session = session_credential.trim();
    let principal = authority.principal_id.as_str();
    let station = authority.station_id.as_str();
    let device = device_id.as_str();
    if base.is_empty()
        || session.is_empty()
        || principal.is_empty()
        || station.is_empty()
        || device.is_empty()
    {
        return None;
    }

    let mut token_hash = DefaultHasher::new();
    session.hash(&mut token_hash);
    Some(format!(
        "{base}|{principal}|{station}|{device}|{:016x}",
        token_hash.finish()
    ))
}

pub(crate) fn local_mls_key_package_publish_hint(
    base_url: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> String {
    let base_scope = server_key(base_url);
    if base_scope.is_empty() {
        return "not-ready".to_owned();
    }
    local_mls_key_material_hint(authority, device_id)
        .unwrap_or_else(|error| format!("error:{error}"))
}

pub(crate) fn local_mls_key_material_hint(
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<String, String> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let inventory = crate::mls::runtime::load_mls_key_package_inventory(
        secure_store.as_ref(),
        authority,
        device_id,
    )
    .map_err(|error| error.to_string())?;
    let mut available = Vec::new();
    for entry in inventory.entries.values() {
        if crate::mls::runtime::load_mls_key_package_identity_state(
            secure_store.as_ref(),
            authority,
            device_id,
            &entry.keypackage_id,
        )
        .map_err(|error| error.to_string())?
        .is_some()
        {
            available.push(entry.keypackage_id.as_str());
        }
    }
    available.sort_unstable();
    arkret_sdk::canonical::canonical_sha256(&available).map_err(|error| error.to_string())
}

pub(crate) async fn ensure_local_mls_key_package_inventory(
    base_url: String,
    session_credential: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
) -> Result<Option<String>, String> {
    let base_scope = server_key(&base_url);
    if base_scope.is_empty() || session_credential.trim().is_empty() {
        return Ok(None);
    }
    Ok(
        maintain_local_mls_key_packages(&base_url, &session_credential, &authority, &device_id)
            .await?
            .latest_key_package_id,
    )
}

pub(crate) async fn manual_refill_local_mls_key_packages(
    base_url: String,
    session_credential: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
) -> Result<usize, String> {
    let base_scope = server_key(&base_url);
    if base_scope.is_empty() || session_credential.trim().is_empty() {
        return Ok(0);
    }
    Ok(
        maintain_local_mls_key_packages(&base_url, &session_credential, &authority, &device_id)
            .await?
            .published_count,
    )
}

struct LocalMlsKeyPackageMaintenanceOutcome {
    latest_key_package_id: Option<String>,
    published_count: usize,
}

async fn maintain_local_mls_key_packages(
    base_url: &str,
    session_credential: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<LocalMlsKeyPackageMaintenanceOutcome, String> {
    let Some(lease) = crate::keypackage_maintenance::acquire(base_url, authority, device_id)
        .await
        .map_err(|error| format!("acquire MLS KeyPackage maintenance lease: {error}"))?
    else {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let inventory = crate::mls::runtime::load_mls_key_package_inventory(
            secure_store.as_ref(),
            authority,
            device_id,
        )
        .map_err(|error| format!("load local MLS KeyPackage inventory: {error}"))?;
        return Ok(LocalMlsKeyPackageMaintenanceOutcome {
            latest_key_package_id: inventory
                .entries
                .values()
                .next_back()
                .map(|entry| entry.keypackage_id.clone()),
            published_count: 0,
        });
    };

    let outcome = run_local_mls_key_package_maintenance_cycle(
        base_url,
        session_credential,
        authority,
        device_id,
    )
    .await;
    let release = lease
        .release()
        .await
        .map_err(|error| format!("release MLS KeyPackage maintenance lease: {error}"));
    match (outcome, release) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

async fn run_local_mls_key_package_maintenance_cycle(
    base_url: &str,
    session_credential: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<LocalMlsKeyPackageMaintenanceOutcome, String> {
    const KEYPACKAGE_MIN_AVAILABLE: usize = 8;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let mut inventory = crate::mls::runtime::load_mls_key_package_inventory(
        secure_store.as_ref(),
        authority,
        device_id,
    )
    .map_err(|error| format!("load local MLS KeyPackage inventory: {error}"))?;

    let now = crate::clock::now_utc();
    let mut stale_entries = Vec::new();
    for entry in inventory.entries.values() {
        let private_state_present = crate::mls::runtime::load_mls_key_package_identity_state(
            secure_store.as_ref(),
            authority,
            device_id,
            &entry.keypackage_id,
        )
        .map_err(|error| {
            format!(
                "load MLS KeyPackage identity state {}: {error}",
                entry.keypackage_id
            )
        })?
        .is_some();
        let usable = entry.has_private_state
            && !entry.last_resort
            && entry.state == arkret_sdk::MlsKeyPackageState::Published
            && entry.expires_at > now
            && private_state_present;
        if !usable {
            stale_entries.push(entry.clone());
        }
    }

    let mut revoke_refs = stale_entries
        .iter()
        .filter(|entry| entry.state == arkret_sdk::MlsKeyPackageState::Published)
        .map(|entry| entry.keypackage_ref.as_str().to_owned())
        .collect::<Vec<_>>();
    revoke_refs.sort();
    revoke_refs.dedup();
    if !revoke_refs.is_empty() {
        let revoke_device_id = device_id.clone();
        let outcome = crate::transport::auth::with_endpoint_clients(
            base_url,
            session_credential.to_owned(),
            None,
            |clients| async move {
                clients
                    .mls()
                    .revoke_key_packages(&revoke_device_id, revoke_refs)
                    .await
            },
        )
        .await
        .map_err(|error| format!("revoke stale MLS KeyPackages: {}", error.display()))?;
        let retryable_failures = outcome
            .failures
            .iter()
            .filter(|failure| {
                !matches!(
                    failure.reason_code.as_str(),
                    "already_consumed" | "already_consumed_or_missing" | "not_found"
                )
            })
            .map(|failure| failure.reason_code.as_str())
            .collect::<Vec<_>>();
        if !retryable_failures.is_empty() {
            return Err(format!(
                "revoke stale MLS KeyPackages returned retryable failures: {}",
                retryable_failures.join(",")
            ));
        }
        if !outcome.failures.is_empty() {
            tracing::warn!(
                failure_count = outcome.failures.len(),
                "some stale MLS KeyPackages were already terminal"
            );
        }
    }

    for entry in &stale_entries {
        delete_unpublished_local_mls_key_package_state(
            secure_store.as_ref(),
            authority,
            device_id,
            &entry.keypackage_id,
            entry.keypackage_ref.as_str(),
        );
        inventory.entries.remove(&entry.keypackage_id);
    }
    crate::mls::runtime::store_mls_key_package_inventory(
        secure_store.as_ref(),
        authority,
        device_id,
        &inventory,
    )
    .map_err(|error| format!("store pruned MLS KeyPackage inventory: {error}"))?;

    let deficit = inventory.maintenance_deficit(now, KEYPACKAGE_MIN_AVAILABLE);
    if deficit == 0 {
        return Ok(LocalMlsKeyPackageMaintenanceOutcome {
            latest_key_package_id: inventory
                .entries
                .values()
                .next_back()
                .map(|entry| entry.keypackage_id.clone()),
            published_count: 0,
        });
    }
    let published = publish_fresh_local_mls_key_package_batch(
        base_url,
        session_credential,
        authority,
        device_id,
        secure_store.as_ref(),
        deficit,
    )
    .await?;
    let count = published.len();
    for entry in published {
        inventory.entries.insert(entry.keypackage_id.clone(), entry);
    }
    crate::mls::runtime::store_mls_key_package_inventory(
        secure_store.as_ref(),
        authority,
        device_id,
        &inventory,
    )
    .map_err(|error| format!("store MLS KeyPackage inventory: {error}"))?;
    Ok(LocalMlsKeyPackageMaintenanceOutcome {
        latest_key_package_id: inventory
            .entries
            .values()
            .next_back()
            .map(|entry| entry.keypackage_id.clone()),
        published_count: count,
    })
}

async fn publish_fresh_local_mls_key_package_batch(
    base_url: &str,
    session_credential: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    count: usize,
) -> Result<Vec<arkret_sdk::LocalMlsKeyPackageInventoryEntry>, String> {
    let mut records = Vec::with_capacity(count);
    let mut local_entries = Vec::with_capacity(count);
    for _ in 0..count {
        let identity = crate::mls_api_helpers::ordinary_mls_identity(
            authority.principal_id.clone(),
            device_id.clone(),
        )
        .map_err(|error| format!("create MLS identity: {error}"))?;
        let record = identity
            .key_package_record()
            .map_err(|error| format!("create MLS KeyPackage: {error}"))?;
        let key_package_id = record.keypackage_id.clone();
        let key_package_ref = record.keypackage_ref.as_str().to_owned();
        let private_state = identity
            .export_private_state()
            .map_err(|error| format!("export MLS KeyPackage identity state: {error}"))?;
        // Durably persist the init private key BEFORE the KeyPackage is advertised
        // to the server (below). The init key lives IndexedDB-only with no
        // localStorage mirror, and the plain sync store is fire-and-forget — an
        // unload/reload race would drop it and leave every Welcome addressed to this
        // KeyPackage permanently undecryptable ("no local KeyPackage identity
        // state"). Awaiting the durable write closes that gap: once the server holds
        // the KeyPackage, the local init key is guaranteed on disk.
        crate::mls::runtime::store_mls_key_package_identity_state_durable(
            secure_store,
            authority,
            device_id,
            &key_package_id,
            &private_state,
        )
        .await
        .map_err(|error| format!("store MLS KeyPackage identity state: {error}"))?;
        if key_package_ref != key_package_id {
            crate::mls::runtime::store_mls_key_package_identity_state_durable(
                secure_store,
                authority,
                device_id,
                &key_package_ref,
                &private_state,
            )
            .await
            .map_err(|error| format!("store MLS KeyPackage identity ref state: {error}"))?;
        }
        let expires_at = record
            .expires_at
            .ok_or_else(|| "fresh KeyPackage is missing its finite expiry".to_owned())?;
        local_entries.push(arkret_sdk::LocalMlsKeyPackageInventoryEntry {
            keypackage_id: key_package_id,
            keypackage_ref: record.keypackage_ref.clone(),
            state: arkret_sdk::MlsKeyPackageState::Published,
            has_private_state: true,
            created_at: record.created_at,
            expires_at,
            last_resort: false,
        });
        records.push(record);
    }

    let publish_device_id = device_id.to_string();
    let publish_records = records.clone();
    let outcome = crate::transport::auth::with_endpoint_clients(
        base_url,
        session_credential.to_owned(),
        None,
        |clients| async move {
            clients
                .mls()
                .publish_key_packages(&publish_device_id, &publish_records)
                .await
        },
    )
    .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            for entry in &local_entries {
                delete_unpublished_local_mls_key_package_state(
                    secure_store,
                    authority,
                    device_id,
                    &entry.keypackage_id,
                    entry.keypackage_ref.as_str(),
                );
            }
            return Err(error.display());
        }
    };
    if outcome.accepted as usize != records.len() {
        for entry in &local_entries {
            delete_unpublished_local_mls_key_package_state(
                secure_store,
                authority,
                device_id,
                &entry.keypackage_id,
                entry.keypackage_ref.as_str(),
            );
        }
        return Err(format!(
            "MLS KeyPackage upload rejected: {:?}",
            outcome.rejections
        ));
    }
    Ok(local_entries)
}

fn delete_unpublished_local_mls_key_package_state(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    key_package_id: &str,
    key_package_ref: &str,
) {
    let _ = crate::mls::runtime::delete_mls_key_package_identity_state(
        secure_store,
        authority,
        device_id,
        key_package_id,
    );
    if key_package_ref != key_package_id {
        let _ = crate::mls::runtime::delete_mls_key_package_identity_state(
            secure_store,
            authority,
            device_id,
            key_package_ref,
        );
    }
}

pub(crate) async fn ensure_pairwise_mls_key_package_published(
    base_url: String,
    session_credential: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    realm_id: arkret_sdk::RealmId,
) -> Result<Option<String>, String> {
    let base_scope = server_key(&base_url);
    if base_scope.is_empty() || session_credential.trim().is_empty() {
        return Ok(None);
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    if let Some(key_package_id) = crate::mls::runtime::load_mls_pairwise_key_package_publish_marker(
        secure_store.as_ref(),
        &authority,
        &device_id,
        &realm_id,
    )
    .map_err(|error| format!("load pairwise MLS KeyPackage publish marker: {error}"))?
    {
        match crate::mls::runtime::load_mls_key_package_identity_state(
            secure_store.as_ref(),
            &authority,
            &device_id,
            &key_package_id,
        ) {
            Ok(Some(_)) => return Ok(Some(key_package_id)),
            Ok(None) => {
                crate::mls::runtime::delete_mls_pairwise_key_package_publish_marker(
                    secure_store.as_ref(),
                    &authority,
                    &device_id,
                    &realm_id,
                )
                .map_err(|error| {
                    format!("delete stale pairwise MLS KeyPackage publish marker: {error}")
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "load pairwise MLS KeyPackage identity state: {error}"
                ));
            }
        }
    }

    let material = crate::mls::pairwise_identity::derive_pairwise_signing_material(
        &authority, &device_id, &realm_id,
    )?;
    let verification_method =
        arkret_sdk::DidUrl::new(material.signer.verification_method().to_owned())
            .map_err(|error| format!("invalid pairwise MLS verification method: {error}"))?;
    let identity = arkret_sdk::ArkretMlsIdentity::new_minimal_metadata_pairwise(
        material.actor_id.clone(),
        verification_method,
        arkret_sdk::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&material.signing_seed()),
        ),
    )
    .map_err(|error| format!("create pairwise MLS identity: {error}"))?;
    let record = identity
        .key_package_record()
        .map_err(|error| format!("create pairwise MLS KeyPackage: {error}"))?;
    let key_package_id = record.keypackage_id.clone();
    let key_package_ref = record.keypackage_ref.as_str().to_owned();
    let private_state = identity
        .export_private_state()
        .map_err(|error| format!("export pairwise MLS KeyPackage identity state: {error}"))?;
    crate::mls::runtime::store_mls_key_package_identity_state_durable(
        secure_store.as_ref(),
        &authority,
        &device_id,
        &key_package_id,
        &private_state,
    )
    .await
    .map_err(|error| format!("store pairwise MLS KeyPackage identity state: {error}"))?;
    if key_package_ref != key_package_id {
        crate::mls::runtime::store_mls_key_package_identity_state_durable(
            secure_store.as_ref(),
            &authority,
            &device_id,
            &key_package_ref,
            &private_state,
        )
        .await
        .map_err(|error| format!("store pairwise MLS KeyPackage ref state: {error}"))?;
    }

    let publish_key_package_id = key_package_id.clone();
    let publish_key_package_ref = key_package_ref.clone();
    let publish_realm_id = realm_id.to_string();
    let signer = material.signer.clone();
    let outcome = crate::transport::auth::with_endpoint_clients(
        &base_url,
        session_credential,
        None,
        |clients| async move {
            clients
                .mls()
                .publish_pairwise_key_package(&publish_realm_id, signer.as_ref(), &record)
                .await
        },
    )
    .await
    .map_err(|error| error.display())?;
    if outcome.accepted == 0 {
        let _ = crate::mls::runtime::delete_mls_key_package_identity_state(
            secure_store.as_ref(),
            &authority,
            &device_id,
            &publish_key_package_id,
        );
        if publish_key_package_ref != publish_key_package_id {
            let _ = crate::mls::runtime::delete_mls_key_package_identity_state(
                secure_store.as_ref(),
                &authority,
                &device_id,
                &publish_key_package_ref,
            );
        }
        return Err(format!(
            "pairwise MLS KeyPackage upload rejected: {:?}",
            outcome.rejections
        ));
    }
    crate::mls::runtime::store_mls_pairwise_key_package_publish_marker(
        secure_store.as_ref(),
        &authority,
        &device_id,
        &realm_id,
        &key_package_id,
    )
    .map_err(|error| format!("store pairwise MLS KeyPackage publish marker: {error}"))?;
    Ok(Some(key_package_id))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct MlsWelcomeBootstrapOutcome {
    pub(crate) applied: usize,
}

fn should_ack_mls_welcome_batch(
    can_ack_welcome_batch: bool,
    welcome_outcome: &crate::mls::runtime::WelcomeApplyOutcome,
    durable_snapshot_present: bool,
    persist_error: Option<&str>,
) -> bool {
    can_ack_welcome_batch
        && welcome_outcome.failed == 0
        && (welcome_outcome.applied > 0 || welcome_outcome.skipped_stale > 0)
        && durable_snapshot_present
        && persist_error.is_none()
}

fn merge_durable_local_mls_welcomes_for_realm(
    messages_value: &mut Value,
    local_inbox: &[Value],
    realm_id: &str,
) -> Result<usize, String> {
    // Account subscribe and the explicit query are two views of one queue. The
    // sync dispatcher may durably journal an envelope and ACK the remote batch
    // before this realm-specific bootstrap runs, so recovery must replay that
    // same journal rather than depend on a second server fetch.
    let messages = messages_value
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "device messages response omits messages array".to_owned())?;
    let mut merged = 0;
    let now = crate::clock::now_utc();

    for local in crate::mls::runtime::collect_mls_welcome_messages_for_realm(local_inbox, realm_id)
    {
        if crate::state::to_device_message_expired(&local, now) {
            continue;
        }
        let local_key = crate::state::to_device_message_dedup_key(&local)?;
        let duplicate = messages.iter().find(|message| {
            crate::state::to_device_message_dedup_key(message)
                .is_ok_and(|message_key| message_key == local_key)
        });
        if let Some(existing) = duplicate {
            if existing != &local {
                return Err(format!(
                    "device_message_conflict: envelope changed for {local_key}"
                ));
            }
            continue;
        }
        messages.push(local);
        merged += 1;
    }

    Ok(merged)
}

pub(crate) async fn bootstrap_mls_welcome_for_realm(
    base_url: String,
    session_credential: String,
    actor_id: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    realm_id: String,
    state_store: &crate::runtime::input::StateStoreHandle,
    needs_mls_backup: Option<Signal<bool>>,
) -> Result<MlsWelcomeBootstrapOutcome, String> {
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id).map_err(|error| error.to_string())?,
    };
    bootstrap_mls_welcome_for_scope(
        base_url,
        session_credential,
        actor_id,
        authority,
        device_id,
        scope,
        state_store,
        needs_mls_backup,
    )
    .await
}

pub(crate) async fn bootstrap_mls_welcome_for_scope(
    base_url: String,
    session_credential: String,
    actor_id: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    scope: arkret_sdk::ScopeRef,
    state_store: &crate::runtime::input::StateStoreHandle,
    needs_mls_backup: Option<Signal<bool>>,
) -> Result<MlsWelcomeBootstrapOutcome, String> {
    let realm_id = scope
        .realm_id_opt()
        .ok_or_else(|| "Welcome requires a Realm scope".to_owned())?
        .to_string();
    let circle_id = scope.circle_id().map(|id| id.as_str());
    if session_credential.trim().is_empty() || realm_id.trim().is_empty() {
        return Ok(MlsWelcomeBootstrapOutcome::default());
    }

    let messages = crate::transport::auth::with_endpoint_clients(
        &base_url,
        session_credential.clone(),
        None,
        |clients| async move { clients.keys().receive_device_messages().await },
    )
    .await
    .map_err(|error| error.display())?;
    let ack_token = messages.ack_token.clone();

    // Runs on every target now that OpenMLS builds + runs under wasm32
    // (the browser uses the in-tree OpenMLS via the `js` feature). Previously
    // the wasm branch discarded the device messages and returned the default
    // outcome, which is why a fresh browser never applied a pending Welcome
    // and showed empty/locked encrypted Realms.
    let mut messages_value =
        serde_json::to_value(&messages).map_err(|error| format!("device messages: {error}"))?;
    let mut can_ack_welcome_batch = circle_id.is_none()
        && mls_welcome_batch_is_exclusively_for_realm(&messages_value, &realm_id);
    retain_mls_welcomes_for_realm(&mut messages_value, &realm_id)?;
    let local_inbox = state_store.read(|store| store.welcome_inbox_for_scope(&scope));
    let replayed_local_welcomes =
        merge_durable_local_mls_welcomes_for_realm(&mut messages_value, &local_inbox, &realm_id)?;
    if let Some(messages) = messages_value
        .get_mut("messages")
        .and_then(Value::as_array_mut)
    {
        can_ack_welcome_batch &= messages.iter().all(|message| {
            message
                .get("content")
                .and_then(|content| {
                    serde_json::from_value::<arkret_sdk::MlsWelcomePayload>(content.clone()).ok()
                })
                .is_some_and(|payload| payload.governance_binding.effective_scope() == &scope)
        });
        messages.retain(|message| {
            message
                .get("content")
                .and_then(|content| {
                    serde_json::from_value::<arkret_sdk::MlsWelcomePayload>(content.clone()).ok()
                })
                .is_some_and(|payload| payload.governance_binding.effective_scope() == &scope)
        });
        if messages.len() > 4 {
            messages.truncate(4);
            can_ack_welcome_batch = false;
        }
    }
    if replayed_local_welcomes > 0 {
        tracing::debug!(
            realm = %realm_id,
            replayed_local_welcomes,
            "replayed MLS welcome envelopes from the durable to-device dispatcher inbox"
        );
    }
    let api = crate::transport::auth::authed_api_ready(&base_url, session_credential.clone())
        .await
        .map_err(|error| format!("MLS governance proof client: {error}"))?;
    let has_welcome = messages_value
        .get("messages")
        .and_then(Value::as_array)
        .is_some_and(|messages| {
            messages.iter().any(|message| {
                message.get("kind").and_then(Value::as_str) == Some(event_kind_str::MLS_WELCOME)
            })
        });
    if has_welcome {
        let seal_view = api
            .event_submitter()
            .map_err(|error| format!("MLS governance proof frontier client: {error}"))?
            .seals_frontier_realm_view(&realm_id)
            .await
            .map_err(|error| format!("refresh accepted Seal view before Welcome proof: {error}"))?;
        state_store.write(|store| {
            store.set_realm_seal_view(
                realm_id.clone(),
                crate::state::LocalSealView {
                    frontier: seal_view
                        .seal_basis
                        .leaves
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    // The Station frontier response does not carry a state root.
                    state_root: None,
                    ..Default::default()
                },
            );
        });
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    if has_welcome {
        for reference in crate::mls::runtime::known_welcome_event_refs(&messages_value)? {
            crate::mls::accepted_artifact::fetch_ref(&api, state_store.clone(), &reference)
                .await
                .map_err(|error| error.to_string())?;
        }
    }
    if has_welcome {
        // Enrollment or recovery must already have installed the account MLS
        // root. Re-commit it durably before joining so a page unload cannot
        // leave a snapshot no local secret can open; a Welcome must never mint
        // a replacement root.
        crate::mls::runtime::ensure_existing_account_mls_secret_durable(
            secure_store.as_ref(),
            &authority,
        )
        .await
        .map_err(|error| format!("durably persisting the account MLS secret failed: {error}"))?;
    }
    let snapshot_before = state_store.read(|store| {
        store
            .mls_checkpoint_for_effective_scope(&realm_id, circle_id)
            .is_some()
    });
    let mut converged =
        crate::mls::runtime::converge_accepted_mls_artifacts(state_store, &authority, &device_id)
            .await?;
    if !state_store.read(|store| {
        store
            .mls_checkpoint_for_effective_scope(&realm_id, circle_id)
            .is_some()
    }) {
        converged +=
            discover_mls_welcome_for_scope(&api, state_store, &authority, &device_id, &scope)
                .await?;
    }
    let snapshot_after = state_store.read(|store| {
        store
            .mls_checkpoint_for_effective_scope(&realm_id, circle_id)
            .is_some()
    });
    let consumable_claims = state_store.read(|store| {
        crate::mls::runtime::accepted_welcome_consume_candidates(
            &store.accepted_mls_artifact_snapshot().snapshot,
            &scope,
        )
    });
    let welcome_outcome = crate::mls::runtime::WelcomeApplyOutcome {
        applied: usize::from(!snapshot_before && snapshot_after && converged > 0),
        failed: 0,
        skipped_stale: usize::from(snapshot_before && snapshot_after),
        first_error: None,
        consumable_claims,
    };

    // Persist Welcome envelopes in the local to-device inbox as well. This
    // bootstrap path fetches and acknowledges them without passing through the
    // normal sync engine, so the explicit ingest preserves the same durable
    // device-message accounting as an ordinary sync delivery.
    if !messages.messages.is_empty() {
        let ingested =
            state_store.write(|store| store.ingest_to_device_messages(&messages.messages));
        tracing::debug!(
            realm = %realm_id,
            ingested,
            "ingested MLS welcome envelopes into to-device inbox for history provider discovery"
        );
    }

    // Welcomes were present but some/all failed to apply: report (do not fail
    // the boot when others succeeded). A totally-empty welcome set has
    // `failed == 0` and is silent.
    if welcome_outcome.failed > 0 {
        tracing::warn!(
            realm = %realm_id,
            applied = welcome_outcome.applied,
            failed = welcome_outcome.failed,
            first_error = welcome_outcome.first_error.as_deref().unwrap_or(""),
            "some MLS welcome(s) failed to apply"
        );
        if let Some(error) = terminal_welcome_apply_error(&welcome_outcome) {
            return Err(error);
        }
    }

    let applied = welcome_outcome.applied;
    if applied > 0 || welcome_outcome.skipped_stale > 0 {
        let barrier = state_store
            .read(crate::state::LocalStateStore::begin_durable_flush)
            .map_err(|error| format!("begin durable MLS Welcome persist: {error}"))?;
        barrier
            .wait()
            .await
            .map_err(|error| format!("persist MLS Welcome state: {error}"))?;
    }
    if applied == 0 && welcome_outcome.skipped_stale == 0 {
        return Ok(MlsWelcomeBootstrapOutcome::default());
    }
    if let Some(error) = state_store.read(|store| store.persist_error()) {
        return Err(format!(
            "local state was not durably persisted after MLS Welcome: {error}"
        ));
    }

    for candidate in &welcome_outcome.consumable_claims {
        let candidate = candidate.clone();
        let consume_request = crate::mls::runtime::sign_welcome_consume_request(
            secure_store.as_ref(),
            &authority,
            &device_id,
            &candidate,
        )
        .await?;
        let key_package_id = candidate.key_package_id.clone();
        let consume = crate::transport::auth::with_endpoint_clients(
            &base_url,
            session_credential.clone(),
            None,
            |clients| async move { clients.mls().consume_key_package(&consume_request).await },
        )
        .await
        .map_err(|error| error.display())?;
        if consume
            .consume_receipt
            .recipient_durable_receipt
            .key_package_ref
            .as_str()
            != key_package_id
        {
            return Err(format!(
                "MLS KeyPackage consume did not confirm {key_package_id}"
            ));
        }
    }

    if applied > 0
        && let Some(needs_mls_backup) = needs_mls_backup
    {
        // Applying a Welcome creates/imports the local account MLS secret before
        // the user necessarily sends an encrypted message. Back it up with the
        // cached recovery public key when available, otherwise surface the prompt.
        crate::components::maybe_auto_backup_mls_after_encrypted_write(
            base_url.clone(),
            session_credential.clone(),
            authority.clone(),
            actor_id.clone(),
            device_id.to_string(),
            state_store.clone(),
            needs_mls_backup,
        )
        .await;
    }

    let Some(_snapshot) =
        state_store.read(|store| store.mls_checkpoint_for_effective_scope(&realm_id, circle_id))
    else {
        return Err("MLS Welcome batch had no durable local MLS snapshot".to_owned());
    };
    if applied > 0 || welcome_outcome.skipped_stale > 0 {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let consumed_pairwise = welcome_outcome.consumable_claims.iter().any(|candidate| {
            matches!(
                candidate.recipient,
                arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise { .. }
            )
        });
        let consumed_device = welcome_outcome.consumable_claims.iter().any(|candidate| {
            matches!(
                candidate.recipient,
                arkret_sdk::MlsWelcomeRecipient::Device { .. }
            )
        });
        if consumed_device {
            let consumed = welcome_outcome
                .consumable_claims
                .iter()
                .filter(|candidate| {
                    matches!(
                        candidate.recipient,
                        arkret_sdk::MlsWelcomeRecipient::Device { .. }
                    )
                })
                .map(|candidate| candidate.key_package_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let mut inventory = crate::mls::runtime::load_mls_key_package_inventory(
                secure_store.as_ref(),
                &authority,
                &device_id,
            )
            .map_err(|error| format!("load claimed MLS KeyPackage inventory: {error}"))?;
            inventory.entries.retain(|_, entry| {
                !consumed.contains(entry.keypackage_id.as_str())
                    && !consumed.contains(entry.keypackage_ref.as_str())
            });
            crate::mls::runtime::store_mls_key_package_inventory(
                secure_store.as_ref(),
                &authority,
                &device_id,
                &inventory,
            )
            .map_err(|error| format!("store claimed MLS KeyPackage inventory: {error}"))?;
            ensure_local_mls_key_package_inventory(
                base_url.clone(),
                session_credential.clone(),
                authority.clone(),
                device_id.clone(),
            )
            .await?;
        }
        if consumed_pairwise {
            let typed_realm_id = arkret_sdk::RealmId::new(realm_id.clone())
                .map_err(|error| format!("invalid pairwise Welcome Realm id: {error}"))?;
            crate::mls::runtime::delete_mls_pairwise_key_package_publish_marker(
                secure_store.as_ref(),
                &authority,
                &device_id,
                &typed_realm_id,
            )
            .map_err(|error| {
                format!("clear claimed pairwise MLS KeyPackage publish marker: {error}")
            })?;
            ensure_pairwise_mls_key_package_published(
                base_url.clone(),
                session_credential.clone(),
                authority,
                device_id,
                typed_realm_id,
            )
            .await?;
        }
    }

    let persist_error = state_store.read(|store| store.persist_error());
    if should_ack_mls_welcome_batch(
        can_ack_welcome_batch,
        &welcome_outcome,
        true,
        persist_error.as_deref(),
    ) && let Some(ack_token) = ack_token
        && let Err(error) = crate::transport::auth::with_endpoint_clients(
            &base_url,
            session_credential.clone(),
            None,
            |clients| async move { clients.keys().ack_device_messages(&ack_token).await },
        )
        .await
    {
        tracing::debug!(?error, "failed to ack durable MLS welcome device messages");
    }

    Ok(MlsWelcomeBootstrapOutcome { applied })
}

/// Discover exact recipient refs without creating device-message deliveries or ACKs.
async fn discover_mls_welcome_for_scope(
    api: &crate::transport::TransportClient,
    state: &crate::runtime::input::StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    scope: &arkret_sdk::ScopeRef,
) -> Result<usize, String> {
    tokio::select! {
        result = discover_mls_welcome_page(api, state, authority, device, scope) => result,
        _ = crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(12)) => {
            Err("MLS Welcome discovery is pending; its per-activation time budget elapsed".to_owned())
        }
    }
}

async fn discover_mls_welcome_page(
    api: &crate::transport::TransportClient,
    state: &crate::runtime::input::StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    scope: &arkret_sdk::ScopeRef,
) -> Result<usize, String> {
    let session_epoch = crate::identity::device_directory::cache_epoch();
    let interest = state.read(|store| store.sync_demand_filter());
    let ensure_current = || {
        if crate::identity::device_directory::cache_epoch() != session_epoch
            || !state.read(|store| {
                store.active_authority().as_ref() == Some(authority)
                    && store.sync_demand_filter() == interest
                    && store.persist_error().is_none()
            })
        {
            return Err("MLS Welcome discovery session or selected interest changed".to_owned());
        }
        Ok(())
    };
    let realm = scope
        .realm_id_opt()
        .ok_or_else(|| "MLS discovery requires a Realm".to_owned())?;
    let circle = scope.circle_id().map(|id| id.as_str());
    let http = api.sdk_http_client().map_err(|error| error.to_string())?;
    let mut request = arkret_sdk::MlsWelcomeRefsRequestBody {
        effective_scope: scope.clone(),
        mls_group_id: arkret_sdk::Base64UrlString::new(
            scope
                .canonical_mls_group_id()
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?,
        limit: Some(4),
        cursor: None,
    };
    let key = serde_json::to_string(&(authority, device, scope, &request.mls_group_id))
        .map_err(|error| error.to_string())?;
    let mut progress = state.read(|store| store.welcome_discovery_progress(&key));
    let frontier = state.read(|store| store.seal_view_for_realm(realm.as_str()).frontier);
    let key_material_hint = local_mls_key_material_hint(authority, device)?;
    progress.observe_inputs(frontier, key_material_hint);
    if progress.exhausted {
        return Ok(0);
    }
    request.cursor = progress.cursor.clone();
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let mut applied = 0;
    // One page and at most four exact artifacts per user-demand activation.
    // Progress survives interruption, so another activation resumes this scope.
    if progress.pending.is_empty() {
        ensure_current()?;
        let page = match http.mls_welcome_refs(&request).await {
            Ok(page) => page,
            Err(error) => {
                ensure_current()?;
                if matches!(&error, arkret_sdk::http_client::Error::Api { error, .. }
                    if error.code() == "cursor_invalid")
                {
                    persist_welcome_discovery_progress(state, &key, None).await?;
                }
                return Err(error.to_string());
            }
        };
        ensure_current()?;
        progress.pending = page.welcome_refs;
        progress.next_cursor = page.next_cursor;
        if progress.pending.is_empty() {
            progress.exhausted = true;
        }
        persist_welcome_discovery_progress(state, &key, Some(progress.clone())).await?;
    }
    for _ in 0..4 {
        let Some(reference) = progress.pending.first().cloned() else {
            break;
        };
        ensure_current()?;
        crate::mls::runtime::ensure_existing_account_mls_secret_durable(
            secure_store.as_ref(),
            authority,
        )
        .await
        .map_err(|error| error.to_string())?;
        ensure_current()?;
        let artifact = crate::mls::accepted_artifact::fetch_ref(api, state.clone(), &reference)
            .await
            .map_err(|error| error.to_string())?;
        ensure_current()?;
        if artifact.event.kind != arkret_sdk::EventKind::MlsWelcome
            || artifact.request.effective_scope != *scope
            || artifact.request.mls_group_id != request.mls_group_id
        {
            return Err(
                "Welcome discovery returned an artifact outside its exact scope/group".to_owned(),
            );
        }
        applied +=
            crate::mls::runtime::converge_accepted_mls_artifacts(state, authority, device).await?;
        ensure_current()?;
        progress.pending.remove(0);
        if progress.pending.is_empty() {
            progress.cursor = progress.next_cursor.take();
            progress.exhausted = progress.cursor.is_none();
        }
        persist_welcome_discovery_progress(state, &key, Some(progress.clone())).await?;
        if state.read(|store| {
            store
                .mls_checkpoint_for_effective_scope(realm.as_str(), circle)
                .is_some()
        }) {
            return Ok(applied);
        }
    }
    Ok(applied)
}

async fn persist_welcome_discovery_progress(
    state: &crate::runtime::input::StateStoreHandle,
    key: &str,
    progress: Option<crate::state::MlsWelcomeDiscoveryProgress>,
) -> Result<(), String> {
    let barrier = state
        .write(|store| {
            store.save_welcome_discovery_progress(key.to_owned(), progress)?;
            store.begin_durable_flush()
        })
        .map_err(|error| error.to_string())?;
    barrier.wait().await.map_err(|error| error.to_string())
}

fn terminal_welcome_apply_error(
    outcome: &crate::mls::runtime::WelcomeApplyOutcome,
) -> Option<String> {
    (outcome.failed > 0 && outcome.applied == 0 && outcome.skipped_stale == 0).then(|| {
        format!(
            "MLS Welcome could not be applied: {}",
            outcome
                .first_error
                .as_deref()
                .unwrap_or("unknown MLS Welcome error")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn durable_welcome(device_message_id: &str, realm_id: &str) -> Value {
        serde_json::json!({
            "device_message_id": device_message_id,
            "kind": "ak.mls.welcome",
            "sender_account_id": {
                "principal_id": "ak:did_core:webvh:alice.example",
                "station_id": "ak:did_core:webvh:station.example"
            },
            "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "recipient_account_id": {
                "principal_id": "ak:did_core:webvh:bob.example",
                "station_id": "ak:did_core:webvh:station.example"
            },
            "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
            "sent_at": "2099-01-01T00:00:00.000Z",
            "expires_at": "2100-01-01T00:00:00.000Z",
            "content": {
                "mls_group_id": garth::mls::welcome_admission::mls_group_id_for_realm(realm_id).unwrap(),
                "ciphertext": "welcome-ciphertext"
            }
        })
    }

    fn welcome_outcome(
        applied: usize,
        failed: usize,
        skipped_stale: usize,
    ) -> crate::mls::runtime::WelcomeApplyOutcome {
        crate::mls::runtime::WelcomeApplyOutcome {
            applied,
            failed,
            skipped_stale,
            first_error: None,
            consumable_claims: Vec::new(),
        }
    }

    #[test]
    fn fully_failed_welcome_batch_is_not_silently_treated_as_empty() {
        let mut outcome = welcome_outcome(0, 1, 0);
        outcome.first_error = Some("missing KeyPackage private state".to_owned());

        let error = terminal_welcome_apply_error(&outcome).expect("terminal failure");
        assert!(error.contains("missing KeyPackage private state"));
        assert!(terminal_welcome_apply_error(&welcome_outcome(1, 1, 0)).is_none());
        assert!(terminal_welcome_apply_error(&welcome_outcome(0, 0, 0)).is_none());
    }

    #[test]
    fn mls_welcome_ack_requires_backup_upload_and_clean_persist() {
        let outcome = welcome_outcome(1, 0, 0);

        assert!(!should_ack_mls_welcome_batch(true, &outcome, false, None));
        assert!(should_ack_mls_welcome_batch(true, &outcome, true, None));
        assert!(!should_ack_mls_welcome_batch(
            true,
            &outcome,
            true,
            Some("state write failed"),
        ));
        assert!(!should_ack_mls_welcome_batch(false, &outcome, true, None));
    }

    #[test]
    fn mls_welcome_ack_rejects_failed_or_unbacked_stale_replay() {
        let failed = welcome_outcome(1, 1, 0);
        assert!(!should_ack_mls_welcome_batch(true, &failed, true, None));

        let stale = welcome_outcome(0, 0, 1);
        assert!(!should_ack_mls_welcome_batch(true, &stale, false, None));
        assert!(should_ack_mls_welcome_batch(true, &stale, true, None));

        let empty = welcome_outcome(0, 0, 0);
        assert!(!should_ack_mls_welcome_batch(true, &empty, true, None));
    }

    #[test]
    fn bootstrap_merges_realm_welcome_from_durable_dispatcher_inbox() {
        let realm_id = "ak:realm:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg";
        let welcome = durable_welcome(
            "ak:device_message:0196419b-0000-7000-8000-000000000021",
            realm_id,
        );
        let mut messages = serde_json::json!({ "messages": [] });

        assert_eq!(
            merge_durable_local_mls_welcomes_for_realm(
                &mut messages,
                std::slice::from_ref(&welcome),
                realm_id,
            )
            .expect("merge durable welcome"),
            1
        );
        assert_eq!(messages["messages"], serde_json::json!([welcome]));
    }

    #[test]
    fn bootstrap_deduplicates_identical_durable_welcome_and_rejects_conflict() {
        let realm_id = "ak:realm:AZiQUXWgexBvj0pdmSuNERtMTAFCjqds5-eP8K9OsgEo";
        let welcome = durable_welcome(
            "ak:device_message:0196419b-0000-7000-8000-000000000022",
            realm_id,
        );
        let mut messages = serde_json::json!({ "messages": [welcome.clone()] });

        assert_eq!(
            merge_durable_local_mls_welcomes_for_realm(
                &mut messages,
                std::slice::from_ref(&welcome),
                realm_id,
            )
            .expect("deduplicate durable welcome"),
            0
        );
        assert_eq!(messages["messages"].as_array().map(Vec::len), Some(1));

        let mut conflicting = welcome;
        conflicting["content"]["ciphertext"] = Value::String("changed".to_owned());
        let error =
            merge_durable_local_mls_welcomes_for_realm(&mut messages, &[conflicting], realm_id)
                .expect_err("same durable dedup key with changed content must fail closed");
        assert!(error.contains("device_message_conflict"));
    }

    #[test]
    fn bootstrap_ignores_unrelated_and_expired_local_messages() {
        let realm_id = "ak:realm:AYo4JWk3bfuR2mX8uX3xALbEPXprrdP2ZWF-dKYP01Wf";
        let mut other_kind = durable_welcome(
            "ak:device_message:0196419b-0000-7000-8000-000000000023",
            realm_id,
        );
        other_kind["kind"] = Value::String("ak.secret.send".to_owned());
        let other_realm = durable_welcome(
            "ak:device_message:0196419b-0000-7000-8000-000000000024",
            "ak:realm:AVtcXI0sfnw9Pex-qynbBUykPtV8niszMj0Ko75SINJ2",
        );
        let mut expired = durable_welcome(
            "ak:device_message:0196419b-0000-7000-8000-000000000025",
            realm_id,
        );
        expired["expires_at"] = Value::String("2000-01-01T00:00:00.000Z".to_owned());
        let mut messages = serde_json::json!({ "messages": [] });

        assert_eq!(
            merge_durable_local_mls_welcomes_for_realm(
                &mut messages,
                &[other_kind, other_realm, expired],
                realm_id,
            )
            .expect("ignore non-matching durable messages"),
            0
        );
        assert_eq!(messages["messages"], serde_json::json!([]));
    }
}
