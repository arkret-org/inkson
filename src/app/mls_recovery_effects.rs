use std::rc::Rc;

use glory::prelude::*;

use super::*;
use crate::presentation::InksonContext;

pub(super) fn install(scope: &Scope, context: Rc<InksonContext>) {
    let mls_unlock_detection_key_seen = scope.cage(None::<String>);
    let needs_mls_unlock = context.needs_mls_unlock;
    let needs_mls_backup = context.needs_mls_backup;
    let needs_mls_recovery_setup = context.needs_mls_recovery_setup;
    let mls_restore_payload_cache = context.restore_payload_cache;
    let secure_store_bootstrap_ready = context.secure_store_bootstrap_ready;
    let account_recovery_configured = context.account_recovery_configured;
    let token = context.token;
    let sync_generation = context.sync_generation;
    let session_boot_state = context.session_boot_state;
    let active_account = context.active_account;
    let route = context.route;
    let task_scope = scope.clone();
    // D1: detect the account-MLS unlock requirement as soon as a logged-in
    // session finishes bootstrap, without waiting for the user to enter a
    // Space/Board/Document route that runs the per-Realm Welcome bootstrap.
    {
        let seen_detection_key = mls_unlock_detection_key_seen;
        let restore_payload_cache = mls_restore_payload_cache;

        let secure_store_ready_for_detection = secure_store_bootstrap_ready;
        let account_recovery_configured_for_detection = account_recovery_configured;
        scope.effect(move || {
            let _ = context.state_revision.get();
            let state_store_for_detection = context.state_store.clone();
            let on_onboarding_route = matches!(route.get(), crate::routes::Route::Onboarding);
            if on_onboarding_route {
                { let next_value = false; needs_mls_unlock.revise(|current| *current = next_value) };
                { let next_value = false; needs_mls_backup.revise(|current| *current = next_value) };
                { let next_value = false; needs_mls_recovery_setup.revise(|current| *current = next_value) };
                { let next_value = None; restore_payload_cache.revise(|current| *current = next_value) };
                { let next_value = None; seen_detection_key.revise(|current| *current = next_value) };
                return;
            }
            if !secure_store_ready_for_detection.get() {
                return;
            }
            let Some(account) = active_account.get() else {
                return;
            };
            let base = account.server_url.to_string();
            let session = token.get();
            let actor = account.principal_id().to_string();
            let device = account.device_id.clone();
            let authority = account.authority.clone();
            // Keep broad sync completion as a re-evaluation trigger, but do
            // not make its monotonically increasing counter part of the
            // deduplication identity. This effect performs authenticated
            // queries itself; those queries advance sync generation, so
            // including it in `detection_key` creates a self-sustaining
            // backups/query loop even when no recovery fact changed.
            let _sync_generation_trigger = sync_generation.get();
            let account_recovery_configured_value = account_recovery_configured_for_detection.get();
            if !matches!(session_boot_state.get(), SessionBootState::Authenticated) {
                { let next_value = false; needs_mls_unlock.revise(|current| *current = next_value) };
                { let next_value = false; needs_mls_backup.revise(|current| *current = next_value) };
                { let next_value = false; needs_mls_recovery_setup.revise(|current| *current = next_value) };
                { let next_value = None; restore_payload_cache.revise(|current| *current = next_value) };
                { let next_value = None; seen_detection_key.revise(|current| *current = next_value) };
                return;
            }
            if session.trim().is_empty() {
                { let next_value = false; needs_mls_unlock.revise(|current| *current = next_value) };
                { let next_value = false; needs_mls_backup.revise(|current| *current = next_value) };
                { let next_value = false; needs_mls_recovery_setup.revise(|current| *current = next_value) };
                { let next_value = None; restore_payload_cache.revise(|current| *current = next_value) };
                { let next_value = None; seen_detection_key.revise(|current| *current = next_value) };
                return;
            }
            // X10.1: do NOT gate on `sync_bootstrap_complete()` here. A fresh
            // browser sits on Dashboard with sync still pending; the MLS
            // unlock/backup detection only needs a live session + a server
            // `list_key_backups` call, NOT a completed sync. Gating on sync
            // meant the unlock prompt never surfaced on a new device until the
            // user manually entered a Space — i.e. "switched browser, never
            // asked for my passphrase". Run as soon as session/actor/device
            // are present; the `seen_detection_key` guard still prevents
            // repeat runs, and re-running after sync (snap= flips) is handled
            // by the detection key below.
            if base.trim().is_empty() || actor.trim().is_empty() {
                return;
            }
            // BUG X4: the account MLS secret is created lazily on the
            // first encrypted write — at register / first space entry it
            // does not exist yet, so `mls_backup_prompt_required` returns
            // false and this effect would never re-fire to surface the
            // backup prompt once the secret appears. Two changes fix that:
            //   1. Read a `state_store` signal in the *synchronous* effect body
            //      (`has_local_mls_checkpoint`) so the effect re-runs this effect when the first
            //      encrypted write saves a snapshot.
            //   2. Fold the local account-secret presence into the detection key (`sec=`) so the
            //      `seen` guard no longer matches once the secret flips false→true, letting the
            //      detection re-run and re-evaluate the backup prompt.
            let (has_local_mls_checkpoint, has_encrypted_realm_projection, local_mls_epoch_floor, recovery_key_fingerprint) = state_store_for_detection.read(|store| (
                !store.mls_local_checkpoints().is_empty(),
                local_state_has_encrypted_realm(store),
                local_mls_epoch_floor_all(store),
                crate::views::recovery::local_recovery_key_fingerprint(store).unwrap_or_default(),
            ));
            let has_local_account_secret = crate::mls::runtime::load_account_mls_secret(
                crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
                &authority,
            )
            .map(|secret| secret.is_some())
            .unwrap_or(false);
            let local_account_secret_verified = crate::mls::runtime::account_mls_secret_verified(
                crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
                &authority,
            )
            .unwrap_or(false);
            let detection_key = format!(
                "{base}|{actor}|{device}|sec={has_local_account_secret}|verified={local_account_secret_verified}|snap={has_local_mls_checkpoint}|enc={has_encrypted_realm_projection}|epoch={local_mls_epoch_floor}|rk={recovery_key_fingerprint}|recovery={account_recovery_configured_value:?}"
            );
            if seen_detection_key.get().as_deref() == Some(detection_key.as_str()) {
                return;
            }
            { let next_value = Some(detection_key.clone()); seen_detection_key.revise(|current| *current = next_value) };
            let seen_detection_key_for_result = seen_detection_key;
            let should_wait_for_projection = should_wait_for_backup_projection(
                has_local_account_secret,
                has_local_mls_checkpoint,
                has_encrypted_realm_projection,
            );

            let task_context = context.clone();
            if let Err(error) = crate::runtime_helpers::spawn_owned(&task_scope, async move {
                let actor_for_sidecar_restore = actor.clone();
                let device_for_sidecar_restore = device.to_string();
                match crate::transport::auth::with_authed_api(
                    &base,
                    session.clone(),
                    |api| async move {
                        let payload = if should_wait_for_projection {
                            crate::mls::account_recovery::fetch_mls_restore_payload_after_encrypted_projection(
                                &api,
                                &actor_for_sidecar_restore,
                            )
                            .await?
                        } else {
                            // A brand-new account has no MLS material whose
                            // projection could be racing. One list is enough;
                            // the encrypted-state inputs in the detection key
                            // will schedule a retry if that changes later.
                            crate::mls::account_recovery::fetch_mls_restore_payload(
                                &api,
                                &actor_for_sidecar_restore,
                            ).await?
                        };
                        let history_payload_for_local_restore = if has_local_account_secret {
                            Some(
                                crate::mls::account_recovery::fetch_mls_restore_payload_with_unlock_proof(
                                    &api,
                                    &actor_for_sidecar_restore,
                                    &device_for_sidecar_restore,
                                )
                                .await?,
                            )
                        } else {
                            None
                        };
                        let sidecar_body_for_local_restore = if has_local_account_secret {
                            crate::mls::account_recovery::fetch_mls_private_plaintext_backup_body(
                                &api,
                                &actor_for_sidecar_restore,
                                &device_for_sidecar_restore,
                            )
                            .await
                            .ok()
                            .flatten()
                        } else {
                            None
                        };
                        Ok((
                            payload,
                            history_payload_for_local_restore,
                            sidecar_body_for_local_restore,
                        ))
                    },
                )
                .await
                {
                    Ok((
                        payload,
                        history_payload_for_local_restore,
                        sidecar_body_for_local_restore,
                    )) => {
                        if seen_detection_key_for_result.get().as_deref()
                            != Some(detection_key.as_str())
                        {
                            return;
                        }
                        let secure_store =
                            crate::secure_key_store::default_secure_key_store("inkson");
                        let configured_backup_id =
                            history_payload_for_local_restore.as_ref().and_then(
                                crate::mls::account_recovery::select_preferred_mls_account_secret_backup,
                            )
                            .and_then(|backup| {
                                backup
                                    .get("backup_id")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned)
                            });
                        {
                            let store_handle =
                                state_store_for_detection.handle();
                            if let Some(backup_id) = configured_backup_id.as_deref() {
                                store_handle.write(|store| {
                                    crate::components::mark_mls_recovery_backup_configured(
                                        store, backup_id,
                                    );
                                });
                            }
                            if let Some(history_payload) =
                                history_payload_for_local_restore.as_ref()
                            {
                                let report = crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                                    history_payload,
                                    &store_handle,
                                    secure_store.as_ref(),
                                    &authority,
                                    authority.principal_id.as_str(),
                                ).await;
                                if report.failed > 0 {
                                    tracing::warn!(
                                        failed = report.failed,
                                        restored = report.restored,
                                        first_error = ?report.first_error,
                                        "mls history restore from local secret failed"
                                    );
                                }
                            }
                            if let Some(sidecar_body) = sidecar_body_for_local_restore.as_ref() {
                                let sidecar_payload =
                                    serde_json::json!({ "backups": [sidecar_body.clone()] });
                                let report = crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                                    &sidecar_payload,
                                    &store_handle,
                                    secure_store.as_ref(),
                                    &authority,
                                    authority.principal_id.as_str(),
                                ).await;
                                if report.failed > 0 {
                                    tracing::warn!(
                                        failed = report.failed,
                                        restored = report.restored,
                                        first_error = ?report.first_error,
                                        "mls sidecar restore from local secret failed"
                                    );
                                }
                            }
                        }
                        let should_unlock = {
                            crate::mls::account_recovery::mls_restore_prompt_required_after_material(
                                &payload,
                                history_payload_for_local_restore.as_ref(),
                                secure_store.as_ref(),
                                &authority,
                                &actor,
                                device.as_str(),
                            )
                        };
                        // Mutual exclusion (task X3): restore (unlock) always
                        // wins. Only evaluate the backup prompt when restore is
                        // not required.
                        if should_unlock {
                            { let next_value = Some(payload.clone()); restore_payload_cache.revise(|current| *current = next_value) };
                            { let next_value = true; needs_mls_unlock.revise(|current| *current = next_value) };
                            { let next_value = false; needs_mls_backup.revise(|current| *current = next_value) };
                            { let next_value = false; needs_mls_recovery_setup.revise(|current| *current = next_value) };
                        } else {
                            // This is the sole background writer of the unlock
                            // requirement. `seen_detection_key_for_result` above
                            // rejects an older result from this effect, so a
                            // newer complete probe must be allowed to clear a
                            // transient positive result. In particular, first
                            // Realm creation briefly exposes the account backup
                            // before the uploader's local verification fence is
                            // observed; making `true` sticky turns that harmless
                            // projection window into a permanent restore modal
                            // on the device that owns the keys.
                            { let next_value = None; restore_payload_cache.revise(|current| *current = next_value) };
                            { let next_value = false; needs_mls_unlock.revise(|current| *current = next_value) };
                            let should_backup =
                                crate::mls::account_recovery::mls_backup_prompt_required(
                                    history_payload_for_local_restore.as_ref().unwrap_or(&payload),
                                    secure_store.as_ref(),
                                    &authority,
                                );
                            if should_backup {
                                crate::components::maybe_auto_backup_mls_after_encrypted_write(
                                    task_context.clone(),
                                    base.clone(),
                                    session.clone(),
                                    authority.clone(),
                                    actor.clone(),
                                    device.to_string(),
                                    state_store_for_detection.handle(),
                                    needs_mls_backup,
                                )
                                .await;
                            } else {
                                { let next_value = false; needs_mls_backup.revise(|current| *current = next_value) };
                            }
                            let should_recovery_setup = state_store_for_detection.read(|store| {
                                mls_recovery_setup_missing(
                                    &payload,
                                    store,
                                    secure_store.as_ref(),
                                    &authority,
                                    account_recovery_configured_value,
                                )
                            });
                            { let next_value = !should_backup && should_recovery_setup; needs_mls_recovery_setup.revise(|current| *current = next_value) };
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error.display_diagnostic(),
                            "MLS account-secret login unlock detection failed"
                        );
                    }
                }
            }) { task_scope.report_error(error); }
        });
    }
}

fn should_wait_for_backup_projection(
    has_local_account_secret: bool,
    has_local_mls_checkpoint: bool,
    has_encrypted_realm_projection: bool,
) -> bool {
    has_local_account_secret || has_local_mls_checkpoint || has_encrypted_realm_projection
}

#[cfg(test)]
mod tests {
    use super::should_wait_for_backup_projection;

    #[test]
    fn brand_new_account_does_not_poll_for_nonexistent_mls_backups() {
        assert!(!should_wait_for_backup_projection(false, false, false));
    }

    #[test]
    fn existing_encryption_state_allows_a_bounded_projection_retry() {
        assert!(should_wait_for_backup_projection(true, false, false));
        assert!(should_wait_for_backup_projection(false, true, false));
        assert!(should_wait_for_backup_projection(false, false, true));
    }
}
