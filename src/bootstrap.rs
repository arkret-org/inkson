//! Pure functions and small data types for post-login / startup-check effects.
//!
//! YOU-07-001: mechanically moved from `app.rs`; move-only, with no changes to
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
use dioxus::prelude::*;
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
    principal_server_url: &str,
    _actor_id: &str,
) -> bool {
    let state = store.load();
    state.session_grant.as_ref().is_some_and(|grant| {
        crate::identity::session_refresh::grant_matches_principal_server(
            grant,
            principal_server_url,
        ) && !crate::identity::session_refresh::grant_is_dead(grant)
    })
}

pub(crate) fn local_state_has_encrypted_realm(state_store: &LocalStateStore) -> bool {
    state_store
        .load()
        .realm_tree_projections
        .values()
        .any(crate::security_state::realm_projection_is_encrypted)
}

pub(crate) fn local_mls_epoch_floor_all(state_store: &LocalStateStore) -> u64 {
    let mut max_epoch = 0_u64;
    for (realm_id, snapshot) in state_store.mls_snapshots() {
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

pub(crate) fn recovery_setup_prompt_required(account_recovery_configured: Option<bool>) -> bool {
    matches!(account_recovery_configured, Some(false))
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
    actor: &str,
    account_recovery_configured: Option<bool>,
) -> Option<String> {
    if !matches!(account_recovery_configured, Some(false)) {
        return None;
    }
    let fingerprint = crate::views::recovery::local_recovery_key_fingerprint(store, actor)?;
    let prompted_fingerprint = store
        .load_private_data(actor, RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if prompted_fingerprint.as_deref() == Some(fingerprint.as_str()) {
        return None;
    }
    Some(fingerprint)
}

pub(crate) fn recovery_auto_prompt_already_prompted(
    store: &LocalStateStore,
    actor: &str,
    account_recovery_configured: Option<bool>,
) -> bool {
    if recovery_auto_prompt_pending_local_only_fingerprint(
        store,
        actor,
        account_recovery_configured,
    )
    .is_some()
    {
        return false;
    }
    store
        .load_private_data(actor, RECOVERY_AUTO_PROMPT_SHOWN_KEY)
        .is_some()
}

/// Whether the recommended-encryption-floor check was already auto-acknowledged
/// for this account (see [`ENCRYPTION_FLOOR_PROMPT_DISMISSED_KEY`]).
pub(crate) fn encryption_floor_prompt_acknowledged(store: &LocalStateStore, actor: &str) -> bool {
    let actor = actor.trim();
    if actor.is_empty() {
        return false;
    }
    store
        .load_private_data(actor, ENCRYPTION_FLOOR_PROMPT_DISMISSED_KEY)
        .is_some()
}

pub(crate) fn current_device_authorization_from_account_viewer(
    viewer: &Value,
    configured_device_id: &str,
) -> Option<bool> {
    let configured_device = configured_device_id.trim();
    let current_device = viewer
        .get("current_device_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|device| !device.is_empty())
        .unwrap_or(configured_device);
    let devices = viewer.get("devices").and_then(Value::as_array)?;
    if devices.is_empty() {
        return None;
    }

    let current_row = devices
        .iter()
        .find(|device| {
            device
                .get("is_current_session_device")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .or_else(|| {
            if current_device.is_empty() {
                None
            } else {
                devices.iter().find(|device| {
                    device
                        .get("device_id")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        == Some(current_device)
                })
            }
        });

    match current_row {
        Some(device) => device_authorization_from_record(device),
        None => Some(false),
    }
}

pub(crate) fn account_has_other_active_devices_from_account_viewer(
    viewer: &Value,
    configured_device_id: &str,
) -> bool {
    let configured_device = configured_device_id.trim();
    let current_device = viewer
        .get("current_device_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|device| !device.is_empty())
        .unwrap_or(configured_device);
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

fn device_authorization_from_record(device: &Value) -> Option<bool> {
    if device_revoked(device) {
        return Some(false);
    }

    for key in ["verification_state", "verification", "trust_state"] {
        if let Some(state) = device.get(key).and_then(Value::as_str)
            && let Some(authorized) = device_status_authorization(state)
        {
            return Some(authorized);
        }
    }
    if let Some(status) = device.get("status").and_then(Value::as_str)
        && let Some(authorized) = device_status_field_authorization(status)
    {
        return Some(authorized);
    }
    if device
        .get("authorized_at")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Some(true);
    }
    Some(false)
}

fn device_revoked(device: &Value) -> bool {
    device
        .get("revoked_at")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
        || device.get("revoked_at").is_some_and(|value| {
            !value.is_null() && !value.as_str().map(str::trim).unwrap_or_default().is_empty()
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

fn device_status_authorization(status: &str) -> Option<bool> {
    let normalized = status.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    match normalized.as_str() {
        "verified" | "authorized" | "active" | "trusted" => Some(true),
        "unverified"
        | "pending"
        | "pending_authorization"
        | "requires_authorization"
        | "revoked"
        | "disabled"
        | "inactive" => Some(false),
        _ => None,
    }
}

fn device_status_field_authorization(status: &str) -> Option<bool> {
    let normalized = status.trim().to_ascii_lowercase();
    if normalized == "active" {
        return None;
    }
    device_status_authorization(status)
}

fn recovery_public_key_secret_storage_backup_present(list_payload: &Value) -> bool {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|backup| {
            backup.get("backup_kind").and_then(Value::as_str) == Some("secret_storage")
                && backup
                    .get("encryption")
                    .and_then(|encryption| encryption.get("recipient_method"))
                    .and_then(Value::as_str)
                    == Some("recovery_public_key")
        })
}

fn recovery_key_path_configured_for_mls_setup(
    list_payload: &Value,
    state_store: &LocalStateStore,
    actor_id: &str,
    account_recovery_configured: Option<bool>,
) -> bool {
    if matches!(account_recovery_configured, Some(true)) {
        return true;
    }
    if !recovery_public_key_secret_storage_backup_present(list_payload) {
        return false;
    }
    crate::views::recovery::local_recovery_key_fingerprint(state_store, actor_id).is_some()
        || crate::views::recovery::local_recovery_public_key(state_store, actor_id).is_some()
}

pub(crate) fn mls_recovery_setup_missing(
    list_payload: &Value,
    state_store: &LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    account_recovery_configured: Option<bool>,
) -> bool {
    if crate::mls::account_recovery::select_preferred_mls_account_secret_backup(list_payload)
        .is_some()
        || crate::mls::account_recovery::select_mls_account_secret_backup(list_payload).is_some()
    {
        return false;
    }
    if matches!(
        crate::mls::runtime::load_account_mls_secret(secure_store, actor_id),
        Ok(Some(_))
    ) {
        return false;
    }
    if recovery_key_path_configured_for_mls_setup(
        list_payload,
        state_store,
        actor_id,
        account_recovery_configured,
    ) {
        return false;
    }
    local_state_has_encrypted_realm(state_store)
        || !crate::mls::account_recovery::select_mls_history_backups(list_payload).is_empty()
}

pub(crate) fn mls_welcome_bootstrap_key(
    base_url: &str,
    session_credential: &str,
    account_did: &str,
    device_id: &str,
    realm_id: &str,
    e2ee_ready: bool,
    sync_bootstrap_complete: bool,
) -> Option<String> {
    if !e2ee_ready || !sync_bootstrap_complete {
        return None;
    }
    let base = server_key(base_url);
    let session = session_credential.trim();
    let actor = account_did.trim();
    let device = device_id.trim();
    let realm = realm_id.trim();
    if base.is_empty()
        || session.is_empty()
        || actor.is_empty()
        || device.is_empty()
        || realm.is_empty()
    {
        return None;
    }

    let mut token_hash = DefaultHasher::new();
    session.hash(&mut token_hash);
    Some(format!(
        "{base}|{actor}|{device}|{realm}|{:016x}",
        token_hash.finish()
    ))
}

pub(crate) fn mls_key_package_publish_key(
    base_url: &str,
    session_credential: &str,
    account_did: &str,
    device_id: &str,
    e2ee_ready: bool,
    sync_bootstrap_complete: bool,
) -> Option<String> {
    if !e2ee_ready || !sync_bootstrap_complete {
        return None;
    }
    let base = server_key(base_url);
    let session = session_credential.trim();
    let actor = account_did.trim();
    let device = device_id.trim();
    if base.is_empty() || session.is_empty() || actor.is_empty() || device.is_empty() {
        return None;
    }

    let mut token_hash = DefaultHasher::new();
    session.hash(&mut token_hash);
    Some(format!(
        "{base}|{actor}|{device}|{:016x}",
        token_hash.finish()
    ))
}

pub(crate) fn local_mls_key_package_publish_hint(
    base_url: &str,
    actor_id: &str,
    device_id: &str,
) -> String {
    let base_scope = server_key(base_url);
    if base_scope.is_empty() || actor_id.trim().is_empty() || device_id.trim().is_empty() {
        return "not-ready".to_owned();
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    match crate::mls::runtime::load_mls_key_package_publish_marker(
        secure_store.as_ref(),
        &base_scope,
        actor_id,
        device_id,
    ) {
        Ok(Some(key_package_id)) => {
            match crate::mls::runtime::load_mls_key_package_identity_state(
                secure_store.as_ref(),
                actor_id,
                device_id,
                &key_package_id,
            ) {
                Ok(Some(_)) => format!("ready:{key_package_id}"),
                Ok(None) => format!("stale:{key_package_id}"),
                Err(error) => format!("error:{error}"),
            }
        }
        Ok(None) => "none".to_owned(),
        Err(error) => format!("error:{error}"),
    }
}

pub(crate) async fn ensure_local_mls_key_package_published(
    base_url: String,
    session_credential: String,
    actor_id: String,
    device_id: String,
) -> Result<Option<String>, String> {
    let base_scope = server_key(&base_url);
    if base_scope.is_empty()
        || session_credential.trim().is_empty()
        || actor_id.trim().is_empty()
        || device_id.trim().is_empty()
    {
        return Ok(None);
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    if let Some(key_package_id) = crate::mls::runtime::load_mls_key_package_publish_marker(
        secure_store.as_ref(),
        &base_scope,
        &actor_id,
        &device_id,
    )
    .map_err(|error| format!("load MLS KeyPackage publish marker: {error}"))?
    {
        match crate::mls::runtime::load_mls_key_package_identity_state(
            secure_store.as_ref(),
            &actor_id,
            &device_id,
            &key_package_id,
        ) {
            Ok(Some(_)) => return Ok(Some(key_package_id)),
            Ok(None) => {
                crate::mls::runtime::delete_mls_key_package_publish_marker(
                    secure_store.as_ref(),
                    &base_scope,
                    &actor_id,
                    &device_id,
                )
                .map_err(|error| format!("delete stale MLS KeyPackage marker: {error}"))?;
                crate::mls::runtime::delete_mls_key_package_publish_ref(
                    secure_store.as_ref(),
                    &base_scope,
                    &actor_id,
                    &device_id,
                )
                .map_err(|error| format!("delete stale MLS KeyPackage publish ref: {error}"))?;
            }
            Err(error) => {
                return Err(format!("load MLS KeyPackage identity state: {error}"));
            }
        }
    }

    let principal = crate::mls_api_helpers::principal_core_id(&actor_id)
        .map_err(|error| format!("MLS principal_id: {error:?}"))?;
    let device = arkret_sdk::DeviceId::new(device_id.trim().to_owned())
        .map_err(|error| format!("MLS device_id: {error:?}"))?;
    let identity = arkret_sdk::ArkretMlsIdentity::new_basic(principal, device)
        .map_err(|error| format!("create MLS identity: {error}"))?;
    // Publish a single-use KeyPackage. Direct Conversation peer claims must
    // reject last-resort packages, and the successful Welcome path below
    // replenishes this slot after the joined MLS state is durable.
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
        secure_store.as_ref(),
        &actor_id,
        &device_id,
        &key_package_id,
        &private_state,
    )
    .await
    .map_err(|error| format!("store MLS KeyPackage identity state: {error}"))?;
    if key_package_ref != key_package_id {
        crate::mls::runtime::store_mls_key_package_identity_state_durable(
            secure_store.as_ref(),
            &actor_id,
            &device_id,
            &key_package_ref,
            &private_state,
        )
        .await
        .map_err(|error| format!("store MLS KeyPackage identity ref state: {error}"))?;
    }

    let publish_device_id = device_id.clone();
    let publish_key_package_id = key_package_id.clone();
    let publish_key_package_ref = key_package_ref.clone();
    let outcome = crate::transport::auth::with_endpoint_clients(
        &base_url,
        session_credential.clone(),
        None,
        |clients| async move {
            clients
                .mls()
                .publish_key_package(&publish_device_id, &record)
                .await
        },
    )
    .await
    .map_err(|error| error.display())?;
    if outcome.accepted == 0 {
        let _ = crate::mls::runtime::delete_mls_key_package_identity_state(
            secure_store.as_ref(),
            &actor_id,
            &device_id,
            &publish_key_package_id,
        );
        if publish_key_package_ref != publish_key_package_id {
            let _ = crate::mls::runtime::delete_mls_key_package_identity_state(
                secure_store.as_ref(),
                &actor_id,
                &device_id,
                &publish_key_package_ref,
            );
        }
        return Err(format!(
            "MLS KeyPackage upload rejected: {:?}",
            outcome.rejected
        ));
    }
    crate::mls::runtime::store_mls_key_package_publish_marker(
        secure_store.as_ref(),
        &base_scope,
        &actor_id,
        &device_id,
        &key_package_id,
    )
    .map_err(|error| format!("store MLS KeyPackage publish marker: {error}"))?;
    // Keep the server-visible canonical ref durably next to the id marker.
    // Direct Conversation repair dispatch freezes this exact ref as
    // `requester_keypackage_ref`; without it the requester must fail closed
    // instead of guessing which package the peer would claim.
    crate::mls::runtime::store_mls_key_package_publish_ref(
        secure_store.as_ref(),
        &base_scope,
        &actor_id,
        &device_id,
        &key_package_ref,
    )
    .map_err(|error| format!("store MLS KeyPackage publish ref: {error}"))?;
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

fn to_device_envelope_dedup_key(message: &Value) -> Result<(&str, &str, &str), String> {
    let required = |field: &str| {
        message
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("durable to-device envelope omits {field}"))
    };
    Ok((
        required("sender_principal_id")?,
        required("sender_device_id")?,
        required("device_message_id")?,
    ))
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
        let local_key = to_device_envelope_dedup_key(&local)?;
        let duplicate = messages.iter().find(|message| {
            to_device_envelope_dedup_key(message).is_ok_and(|message_key| message_key == local_key)
        });
        if let Some(existing) = duplicate {
            if existing != &local {
                return Err(format!(
                    "device_message_conflict: envelope changed for {}|{}|{}",
                    local_key.0, local_key.1, local_key.2
                ));
            }
            continue;
        }
        messages.push(local);
        merged += 1;
    }

    Ok(merged)
}

fn mls_welcome_batch_is_exclusively_for_realm(value: &Value, realm_id: &str) -> bool {
    value
        .get("messages")
        .and_then(Value::as_array)
        .is_some_and(|messages| {
            !messages.is_empty()
                && messages.iter().all(|message| {
                    crate::mls::runtime::mls_welcome_message_matches_realm(message, realm_id)
                })
        })
}

fn retain_mls_welcomes_for_realm(value: &mut Value, realm_id: &str) -> Result<(), String> {
    value
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "device messages response omits messages array".to_owned())?
        .retain(|message| {
            crate::mls::runtime::mls_welcome_message_matches_realm(message, realm_id)
        });
    Ok(())
}

pub(crate) async fn bootstrap_mls_welcome_for_realm(
    base_url: String,
    session_credential: String,
    actor_id: String,
    device_id: String,
    realm_id: String,
    mut state_store: SyncSignal<LocalStateStore>,
    needs_mls_backup: Option<Signal<bool>>,
) -> Result<MlsWelcomeBootstrapOutcome, String> {
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
    let can_ack_welcome_batch =
        mls_welcome_batch_is_exclusively_for_realm(&messages_value, &realm_id);
    retain_mls_welcomes_for_realm(&mut messages_value, &realm_id)?;
    let local_inbox = state_store.read().to_device_inbox();
    let replayed_local_welcomes =
        merge_durable_local_mls_welcomes_for_realm(&mut messages_value, &local_inbox, &realm_id)?;
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
            .events_frontier_realm_seal_view(&realm_id)
            .await
            .map_err(|error| format!("refresh accepted Seal view before Welcome proof: {error}"))?;
        state_store.write().set_realm_seal_view(
            realm_id.clone(),
            crate::state::LocalSealView {
                frontier: vec![seal_view.seal_id.to_string()],
                state_root: Some(seal_view.state_root.to_string()),
                ..Default::default()
            },
        );
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let previews = crate::mls::runtime::preview_welcome_security_frontiers(
        secure_store.as_ref(),
        &actor_id,
        &device_id,
        &messages_value,
    )?;
    for preview in previews {
        // encryption-and-audit.md 2.5.4 T1 — the invitee's first-time path. The
        // Welcome deliberately carries no anchor: a carried one would be a second,
        // weaker trust source. Knowing realm_id is enough, and the Welcome gives
        // that much.
        crate::mls::governance_proof::ensure_governance_checkpoint(
            &api,
            state_store,
            preview.binding.realm_id().as_str(),
        )
        .await?;
        let request = crate::mls::governance_proof::proof_request_for_scope(
            &state_store.read(),
            preview.binding.effective_scope().clone(),
            preview.binding.mls_group_id(),
            preview.binding.previous_epoch(),
            preview.binding.next_epoch(),
            preview.leaves.clone(),
        )?;
        crate::mls::governance_proof::fetch_verify_and_cache_expected_proof(
            &api,
            state_store,
            &request,
            &preview.leaves,
            &preview.binding,
        )
        .await?;
    }
    if has_welcome {
        // Applying a first Welcome mints the account MLS secret through the
        // sync store surface (detached background persistence on wasm), while
        // the joined group snapshot rides the durable account-state writer.
        // Land the secret durably before joining so a page unload cannot leave
        // a snapshot no local secret can open.
        crate::mls::runtime::ensure_existing_account_mls_secret_durable(
            secure_store.as_ref(),
            &actor_id,
        )
        .await
        .map_err(|error| format!("durably persisting the account MLS secret failed: {error}"))?;
    }
    let welcome_outcome = {
        let mut store = state_store.write();
        crate::mls::runtime::apply_welcome_messages_with_device_snapshot(
            &mut store,
            secure_store.as_ref(),
            &realm_id,
            &actor_id,
            &device_id,
            &messages_value,
        )
    }
    .map_err(|error| error.user_message())?;

    // Persist Welcome envelopes in the local to-device inbox as well. This
    // bootstrap path fetches and acknowledges them without passing through the
    // normal sync engine, so the explicit ingest preserves the same durable
    // device-message accounting as an ordinary sync delivery.
    if !messages.messages.is_empty() {
        let ingested = state_store
            .write()
            .ingest_to_device_messages(&messages.messages);
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
            .read()
            .begin_durable_flush()
            .map_err(|error| format!("begin durable MLS Welcome persist: {error}"))?;
        barrier
            .wait()
            .await
            .map_err(|error| format!("persist MLS Welcome state: {error}"))?;
    }
    if applied == 0 && welcome_outcome.skipped_stale == 0 {
        return Ok(MlsWelcomeBootstrapOutcome::default());
    }
    if let Some(error) = state_store.read().persist_error() {
        return Err(format!(
            "local state was not durably persisted after MLS Welcome: {error}"
        ));
    }

    for candidate in &welcome_outcome.consumable_claims {
        let candidate = candidate.clone();
        let candidate_for_consume = candidate.clone();
        let key_package_id = candidate.key_package_id.clone();
        let consumer_device_id = device_id.clone();
        let consume = crate::transport::auth::with_endpoint_clients(
            &base_url,
            session_credential.clone(),
            None,
            |clients| async move {
                clients
                    .mls()
                    .consume_key_package(&candidate_for_consume, &consumer_device_id)
                    .await
            },
        )
        .await
        .map_err(|error| error.display())?;
        if !consume.failures.is_empty()
            || !consume
                .consumed
                .iter()
                .any(|keypackage_ref| keypackage_ref == &key_package_id)
        {
            return Err(format!(
                "MLS KeyPackage consume did not confirm {}: {:?}",
                key_package_id, consume.failures
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
            actor_id.clone(),
            device_id.clone(),
            state_store,
            needs_mls_backup,
        )
        .await;
    }

    let Some(_snapshot) = state_store.read().mls_snapshot_for(&realm_id) else {
        return Err("MLS Welcome batch had no durable local MLS snapshot".to_owned());
    };
    if applied > 0 || welcome_outcome.skipped_stale > 0 {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let base_scope = server_key(&base_url);
        crate::mls::runtime::delete_mls_key_package_publish_marker(
            secure_store.as_ref(),
            &base_scope,
            &actor_id,
            &device_id,
        )
        .map_err(|error| format!("clear claimed MLS KeyPackage publish marker: {error}"))?;
        crate::mls::runtime::delete_mls_key_package_publish_ref(
            secure_store.as_ref(),
            &base_scope,
            &actor_id,
            &device_id,
        )
        .map_err(|error| format!("clear claimed MLS KeyPackage publish ref: {error}"))?;
        ensure_local_mls_key_package_published(
            base_url.clone(),
            session_credential.clone(),
            actor_id,
            device_id,
        )
        .await?;
    }

    let persist_error = state_store.read().persist_error();
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
            "sender_principal_id": "did:webvh:alice.example",
            "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "recipient_principal_id": "ak:did_core:webvh:bob.example",
            "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
            "sent_at": "2099-01-01T00:00:00.000Z",
            "expires_at": "2100-01-01T00:00:00.000Z",
            "content": {
                "mls_group_id": crate::mls::runtime::mls_group_id_for_realm(realm_id).unwrap(),
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
    fn bootstrap_applies_only_current_realm_welcomes_and_preserves_ack_boundary() {
        let realm_id = "ak:realm:AcQV37Nr-Ulm-nqFSnugsZ9MU-I0QBLO7VHTvtcwYWns";
        let current = durable_welcome(
            "ak:device_message:0196419b-0000-7000-8000-000000000026",
            realm_id,
        );
        let other = durable_welcome(
            "ak:device_message:0196419b-0000-7000-8000-000000000027",
            "ak:realm:AVtcXI0sfnw9Pex-qynbBUykPtV8niszMj0Ko75SINJ2",
        );
        let mut messages = serde_json::json!({
            "messages": [current.clone(), other],
        });

        assert!(!mls_welcome_batch_is_exclusively_for_realm(
            &messages, realm_id
        ));
        retain_mls_welcomes_for_realm(&mut messages, realm_id).unwrap();
        assert_eq!(messages["messages"], serde_json::json!([current]));
        assert!(mls_welcome_batch_is_exclusively_for_realm(
            &messages, realm_id
        ));
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
