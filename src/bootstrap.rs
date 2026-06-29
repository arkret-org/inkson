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

use dioxus::prelude::*;
use serde_json::Value;

use super::server_key;
use crate::local_state::LocalStateStore;

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
        crate::session_refresh::grant_matches_principal_server(grant, principal_server_url)
            && !crate::session_refresh::grant_is_dead(grant)
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
        "verified" | "authorized" | "active" | "cross_signed" | "trusted" => Some(true),
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

fn did_recovery_public_key_backup_present(list_payload: &Value) -> bool {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|backup| {
            backup.get("backup_class").and_then(Value::as_str) == Some("did_recovery")
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
    if !did_recovery_public_key_backup_present(list_payload) {
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
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
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
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
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
            }
            Err(error) => {
                return Err(format!("load MLS KeyPackage identity state: {error}"));
            }
        }
    }

    let principal = cokret_sdk::Did::new(actor_id.trim().to_owned())
        .map_err(|error| format!("MLS principal_id: {error:?}"))?;
    let device = cokret_sdk::DeviceId::new(device_id.trim().to_owned())
        .map_err(|error| format!("MLS device_id: {error:?}"))?;
    let identity = cokret_sdk::CokretMlsIdentity::new_basic(principal, device)
        .map_err(|error| format!("create MLS identity: {error}"))?;
    // Publish a reusable last-resort KeyPackage. Single-use KeyPackages are
    // consumed on claim, so once an admission claims it the member has no
    // claimable KeyPackage left — if that admission's Welcome is ever lost
    // (consumed server-side but never applied client-side, e.g. a Welcome
    // to-device message that expired, or a transient resolution failure during
    // apply), the member becomes permanently un-addable: the admin reconcile
    // loop can never re-admit it and it is stuck "pending invite" forever. A
    // last-resort KeyPackage is kept claimable by the server and retains its
    // init key across repeated Welcomes, so re-admission always succeeds.
    let record = identity
        .last_resort_key_package_record()
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
    let outcome = crate::views::helpers::with_authed_api(
        &base_url,
        session_credential.clone(),
        |api| async move {
            api.publish_mls_key_package(&publish_device_id, &record)
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
    Ok(Some(key_package_id))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct MlsWelcomeBootstrapOutcome {
    pub(crate) applied: usize,
    pub(crate) backup_id: Option<String>,
}

fn should_ack_mls_welcome_batch(
    can_ack_welcome_batch: bool,
    welcome_outcome: &crate::mls::runtime::WelcomeApplyOutcome,
    backup_uploaded: bool,
    persist_error: Option<&str>,
) -> bool {
    can_ack_welcome_batch
        && welcome_outcome.failed == 0
        && (welcome_outcome.applied > 0 || welcome_outcome.skipped_stale > 0)
        && backup_uploaded
        && persist_error.is_none()
}

pub(crate) async fn bootstrap_mls_welcome_for_realm(
    base_url: String,
    session_credential: String,
    actor_id: String,
    device_id: String,
    realm_id: String,
    mut state_store: Signal<LocalStateStore>,
    needs_mls_backup: Signal<bool>,
) -> Result<MlsWelcomeBootstrapOutcome, String> {
    if session_credential.trim().is_empty() || realm_id.trim().is_empty() {
        return Ok(MlsWelcomeBootstrapOutcome::default());
    }

    let messages = crate::views::helpers::with_authed_api(
        &base_url,
        session_credential.clone(),
        |api| async move { api.receive_device_messages().await },
    )
    .await
    .map_err(|error| error.display())?;
    let ack_token = messages.ack_token.clone();
    let can_ack_welcome_batch = !messages.messages.is_empty()
        && messages
            .messages
            .iter()
            .all(|message| message.kind == "ck.mls.welcome");

    // Runs on every target now that OpenMLS builds + runs under wasm32
    // (the browser uses the in-tree OpenMLS via the `js` feature). Previously
    // the wasm branch discarded the device messages and returned the default
    // outcome, which is why a fresh browser never applied a pending Welcome
    // and showed empty/locked encrypted Realms.
    let messages_value =
        serde_json::to_value(&messages).map_err(|error| format!("device messages: {error}"))?;
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
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
    }

    let applied = welcome_outcome.applied;
    if applied == 0 && welcome_outcome.skipped_stale == 0 {
        return Ok(MlsWelcomeBootstrapOutcome::default());
    }
    if let Some(error) = state_store.read().persist_error() {
        return Err(format!(
            "local state was not durably persisted after MLS Welcome: {error}"
        ));
    }

    if applied > 0 {
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

    let Some(snapshot) = state_store.read().mls_snapshot_for(&realm_id) else {
        return Err("MLS Welcome batch had no durable local MLS snapshot".to_owned());
    };
    let base_for_backup = base_url.clone();
    let actor_for_backup = actor_id.clone();
    let device_for_backup = device_id.clone();
    let realm_for_backup = realm_id.clone();
    let backup_id = crate::views::helpers::with_authed_api(
        &base_url,
        session_credential.clone(),
        |api| async move {
            // §7.10: applying a Welcome lands a fresh epoch — chain the upload
            // onto the Realm's existing mls_history series (successor
            // envelope) instead of minting a new genesis series per Welcome.
            crate::components::upload_mls_history_backup_now(
                &api,
                &base_for_backup,
                &actor_for_backup,
                &device_for_backup,
                &realm_for_backup,
                &snapshot,
            )
            .await
        },
    )
    .await
    .map_err(|error| error.display())?;

    let persist_error = state_store.read().persist_error();
    if should_ack_mls_welcome_batch(
        can_ack_welcome_batch,
        &welcome_outcome,
        true,
        persist_error.as_deref(),
    ) && let Some(ack_token) = ack_token
        && let Err(error) = crate::views::helpers::with_authed_api(
            &base_url,
            session_credential.clone(),
            |api| async move { api.ack_device_messages(&ack_token).await },
        )
        .await
    {
        tracing::debug!(?error, "failed to ack durable MLS welcome device messages");
    }

    Ok(MlsWelcomeBootstrapOutcome {
        applied,
        backup_id: Some(backup_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }
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
}
