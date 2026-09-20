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

use dioxus::prelude::Signal;
use garth::mls::backup_selection::recovery_setup_prompt_required;
use serde_json::Value;

use super::server_key;
use crate::state::LocalStateStore;

pub(crate) const RECOVERY_AUTO_PROMPT_SHOWN_KEY: &str = "recovery.auto_prompt_shown.v1";
pub(crate) const RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY: &str =
    "recovery.auto_prompt_local_only_shown.v1";

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
    // A scope is encrypted exactly when its own `ak.mls.genesis` is accepted in
    // the cached typed current results; there is no create-locked
    // `encryption_profile` to read off the stored projection any more. The
    // judgement lives in one place, so ask the store per Realm rather than
    // re-deriving it from the projection JSON here.
    state_store
        .load()
        .realm_tree_projections
        .keys()
        .any(|realm_id| state_store.realm_projection_is_mls_encrypted(realm_id))
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

/// Whether one account-viewer device row reports an accepted authorization.
///
/// `None` means the row does not carry the fact at all, which is not the same
/// answer as "not authorized" and must keep the caller waiting rather than
/// prompting for a fresh authorization.
fn device_authorization_from_record(device: &Value) -> Option<bool> {
    if device_revoked(device) {
        return Some(false);
    }
    device
        .get("authorized")
        .and_then(Value::as_bool)
        .or_else(|| {
            device
                .get("device_authorize_event_id")
                .and_then(Value::as_str)
                .map(|event_id| !event_id.trim().is_empty())
        })
}

/// Whether one account-viewer device row reports a revoked device.
fn device_revoked(device: &Value) -> bool {
    device
        .get("revoked_at")
        .is_some_and(|value| !value.is_null())
        || device.get("revoked").and_then(Value::as_bool) == Some(true)
        || device.get("state").and_then(Value::as_str) == Some("revoked")
}

/// Whether the account has any `recovery_public_key` secret-storage backup at
/// all, in any series.
fn recovery_public_key_secret_storage_backup_present(list_payload: &Value) -> bool {
    crate::mls::runtime::iter_backup_bodies(list_payload)
        .any(crate::mls::runtime::is_recovery_public_key_account_secret_backup)
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
        let identity =
            crate::mls_api_helpers::ordinary_mls_identity(authority.clone(), device_id.clone())
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
        arkret_sdk::ActorId::service(material.actor_id.clone()),
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

/// Whether the drained device-message batch may be acknowledged.
///
/// An ACK deletes the server-side copy, so a batch is only safe to acknowledge
/// once every message it carried has been durably journalled: a partially
/// journalled or unpersisted batch must be redelivered instead.
fn should_ack_device_message_batch(
    journalled_every_message: bool,
    durable_persist_error: Option<&str>,
) -> bool {
    journalled_every_message && durable_persist_error.is_none()
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

/// Drain this device's to-device queue and join every scope it has been
/// Welcomed into.
///
/// A Welcome is no longer an Event and there is no separate Welcome-ref
/// discovery endpoint: the governance Station commits MlsWelcomeDelivery
/// objects in the same transaction as the ak.mls.commit they name and delivers
/// them through the ordinary to-device queue. So the whole bootstrap is: drain
/// the queue into the durable inbox, let the artifact consumer resolve each
/// delivery's accepted Commit on the scope's own independent stream and install
/// it, then acknowledge the batch once it is durably journalled.
///
/// `scope` only selects which scope this activation reports on. The drain
/// itself is account-wide, because one queue batch can carry deliveries for
/// several scopes and discarding the others would lose them at the ACK.
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
    if session_credential.trim().is_empty() {
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
    let delivered = messages.messages.len();

    // The durable inbox is the only source the Welcome installer reads, so the
    // batch is journalled before anything is installed or acknowledged.
    let journalled = if messages.messages.is_empty() {
        0
    } else {
        state_store.write(|store| store.ingest_to_device_messages(&messages.messages))
    };
    if journalled > 0 {
        let barrier = state_store
            .read(crate::state::LocalStateStore::begin_durable_flush)
            .map_err(|error| format!("begin durable to-device journal: {error}"))?;
        barrier
            .wait()
            .await
            .map_err(|error| format!("persist the to-device Welcome journal: {error}"))?;
    }

    let installed_before =
        state_store.read(|store| store.mls_checkpoint_for_scope(&scope).is_some());
    let pending_welcomes = state_store.read(|store| {
        !crate::mls::welcome_delivery::pending_welcome_deliveries(&store.to_device_inbox())
            .is_empty()
    });
    if pending_welcomes {
        // Enrollment or recovery must already have installed the account MLS
        // root. Re-commit it durably before joining so a page unload cannot
        // leave a snapshot no local secret can open; a Welcome must never mint
        // a replacement root.
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        crate::mls::runtime::ensure_existing_account_mls_secret_durable(
            secure_store.as_ref(),
            &authority,
        )
        .await
        .map_err(|error| format!("durably persisting the account MLS secret failed: {error}"))?;
    }
    let api = crate::transport::auth::authed_api_ready(&base_url, session_credential.clone())
        .await
        .map_err(|error| format!("MLS Welcome stream client: {error}"))?;
    let applied = crate::mls::runtime::converge_accepted_mls_artifacts(
        &api,
        state_store,
        &authority,
        &device_id,
    )
    .await?;
    let installed_after =
        state_store.read(|store| store.mls_checkpoint_for_scope(&scope).is_some());

    if applied > 0 {
        let barrier = state_store
            .read(crate::state::LocalStateStore::begin_durable_flush)
            .map_err(|error| format!("begin durable MLS Welcome persist: {error}"))?;
        barrier
            .wait()
            .await
            .map_err(|error| format!("persist MLS Welcome state: {error}"))?;
    }
    let persist_error = state_store.read(|store| store.persist_error());
    if applied > 0
        && let Some(error) = persist_error.as_deref()
    {
        return Err(format!(
            "local state was not durably persisted after MLS Welcome: {error}"
        ));
    }

    if applied > 0
        && let Some(needs_mls_backup) = needs_mls_backup
    {
        // Applying a Welcome imports the local account MLS secret before the
        // user necessarily sends an encrypted message. Back it up with the
        // cached recovery public key when available, otherwise surface the
        // prompt.
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

    if applied > 0 {
        // Joining consumed one of this device's published single-use
        // KeyPackages, so refill the inventory before the next invite can
        // fail with `mls_keypackage_not_found`.
        ensure_local_mls_key_package_inventory(
            base_url.clone(),
            session_credential.clone(),
            authority.clone(),
            device_id.clone(),
        )
        .await?;
        if state_store.read(|store| store.realm_projection_is_minimal_metadata(&realm_id)) {
            let typed_realm_id = arkret_sdk::RealmId::new(realm_id.clone())
                .map_err(|error| format!("invalid pairwise Welcome Realm id: {error}"))?;
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
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

    if should_ack_device_message_batch(journalled == delivered, persist_error.as_deref())
        && let Some(ack_token) = ack_token
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

    tracing::debug!(
        realm = %realm_id,
        delivered,
        journalled,
        applied,
        joined_this_pass = !installed_before && installed_after,
        "MLS Welcome bootstrap pass finished",
    );
    Ok(MlsWelcomeBootstrapOutcome { applied })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One account-viewer device row.
    fn device_row(device_id: &str, extra: serde_json::Value) -> Value {
        let mut row = serde_json::json!({ "device_id": device_id });
        for (key, value) in extra.as_object().unwrap() {
            row[key] = value.clone();
        }
        row
    }

    #[test]
    fn a_revoked_device_is_never_reported_as_authorized() {
        let revoked = device_row(
            "ak:device:0196419b-0000-7000-8000-000000000001",
            serde_json::json!({ "authorized": true, "revoked_at": "2026-01-01T00:00:00.000Z" }),
        );
        assert!(device_revoked(&revoked));
        assert_eq!(device_authorization_from_record(&revoked), Some(false));
    }

    #[test]
    fn a_device_row_without_the_authorization_fact_keeps_the_caller_waiting() {
        let unknown = device_row(
            "ak:device:0196419b-0000-7000-8000-000000000002",
            serde_json::json!({}),
        );
        assert_eq!(device_authorization_from_record(&unknown), None);

        let authorized = device_row(
            "ak:device:0196419b-0000-7000-8000-000000000002",
            serde_json::json!({
                "device_authorize_event_id":
                    "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk"
            }),
        );
        assert_eq!(device_authorization_from_record(&authorized), Some(true));
    }

    #[test]
    fn the_account_viewer_reports_other_active_devices_only_when_they_are_live() {
        let viewer = serde_json::json!({
            "devices": [
                { "device_id": "ak:device:0196419b-0000-7000-8000-000000000001" },
                {
                    "device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
                    "state": "revoked"
                },
            ]
        });
        assert!(!account_has_other_active_devices_from_account_viewer(
            &viewer,
            "ak:device:0196419b-0000-7000-8000-000000000001"
        ));
        assert!(account_has_other_active_devices_from_account_viewer(
            &viewer,
            "ak:device:0196419b-0000-7000-8000-000000000002"
        ));
    }

    #[test]
    fn a_batch_is_acknowledged_only_after_every_message_is_durably_journalled() {
        // The ACK deletes the server-side copy, so a partially journalled or
        // unpersisted batch must be redelivered instead of acknowledged.
        assert!(should_ack_device_message_batch(true, None));
        assert!(!should_ack_device_message_batch(false, None));
        assert!(!should_ack_device_message_batch(
            true,
            Some("state write failed")
        ));
    }

    #[test]
    fn a_recovery_public_key_backup_is_detected_in_any_series() {
        let list = serde_json::json!({
            "backups": [{
                "backup_kind": "secret_storage",
                "series_id": "ak:backup_series:0196419b-0000-7000-8000-00000000000a",
                "series_seq": 0,
                "encryption": { "recipient_method": "recovery_public_key" },
                "contents": [{ "item_kind": "mls_account_secret" }],
            }]
        });
        assert!(recovery_public_key_secret_storage_backup_present(&list));
        assert!(!recovery_public_key_secret_storage_backup_present(
            &serde_json::json!({ "backups": [] })
        ));
    }
}
