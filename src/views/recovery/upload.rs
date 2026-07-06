//! RK-as-authority server backup flow.

use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::views::helpers::with_authed_api;

/// RK-as-authority backup: publish the active recovery policy and a
/// `did_recovery` backup immediately, then create or load the account MLS
/// secret and wrap it behind the just generated 24-word Recovery Key. This
/// keeps the server-side first-backup gate satisfied and closes the window
/// where a user has DID recovery but no fresh-device content bootstrap path.
/// Outcome of attempting to establish a freshly generated account Recovery Key
/// on the server, reported back to the setup prompt so it can stay fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryKeyBackupOutcome {
    /// Server accepted the recovery policy + DID-recovery (and, when present,
    /// account-secret) backup. Only now may the device reveal the 24 words.
    /// Local recovery metadata (fingerprint / rotated_at / public key) stays
    /// pending until the user passes the transcription check — the caller
    /// finalizes it via `save_generated_recovery_key_metadata` on verify
    /// success, so an abandoned enrollment never claims to be configured.
    Established,
    /// The server refused because this session device is not an authorized,
    /// verified key-management device (`device_not_authorized`). The generated
    /// key MUST be discarded — never persisted, never shown — and the user
    /// routed to device authorization / restore-with-existing-Recovery-Key.
    DeviceNotAuthorized,
    /// A transient failure (network / 5xx / not-yet-authenticated). Nothing was
    /// established; the caller may retry without having leaked or persisted a
    /// divergent key.
    Transient,
}

pub(crate) fn upload_recovery_key_account_backup(
    base_url: String,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
    recovery_key: String,
    mut status: Signal<String>,
    on_server_configured: Option<EventHandler<()>>,
    on_outcome: Option<EventHandler<RecoveryKeyBackupOutcome>>,
) {
    let Some(recovery_secret) = crate::recovery_crypto::normalize_recovery_key_input(&recovery_key)
    else {
        return;
    };
    let base = base_url;
    let session = token();
    let actor = account_did();
    let device = device_id();
    if base.trim().is_empty() || session.trim().is_empty() || actor.trim().is_empty() {
        if let Some(handler) = on_outcome {
            handler.call(RecoveryKeyBackupOutcome::Transient);
        }
        return;
    }
    let sidecar_json = if state_store.read().private_plaintext_is_empty() {
        None
    } else {
        Some(state_store.read().private_plaintext_snapshot_json())
    };
    let needs_mls_backup_signal = crate::components::try_needs_mls_backup_signal();
    status.set(
        "Recovery Key generated — publishing recovery policy and DID recovery backup…".to_owned(),
    );
    spawn(async move {
        let actor_for_sidecar = actor.clone();
        let device_for_sidecar = device.clone();
        let base_for_sidecar = base.clone();
        let session_for_sidecar = session.clone();
        let mut state_store = state_store;
        let result = with_authed_api(&base, session, |api| async move {
            let did_backup_id =
                crate::recovery_strand::ensure_recovery_policy_and_did_recovery_backup(
                    &api,
                    &actor,
                    &device,
                    &recovery_secret,
                )
                .await?;
            let secure = crate::secure_key_store::default_secure_key_store("yougen");
            crate::mls::runtime::load_or_create_account_mls_secret(
                secure.as_ref(),
                &actor,
                &device,
            )
            .map_err(|err| anyhow::anyhow!("ensure account MLS secret before backup: {err}"))?;
            let account_backup_id = Some(
                crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key(
                    &api,
                    secure.as_ref(),
                    &actor,
                    &device,
                    &recovery_secret,
                )
                .await?,
            );
            Ok::<_, anyhow::Error>((did_backup_id, account_backup_id))
        })
        .await;
        match result {
            Ok((did_backup_id, account_backup_id)) => {
                // Fail-closed ordering: the server accepted the backup, so this
                // device is an authorized key-management device and the caller
                // may now reveal the 24 words. Local recovery metadata is NOT
                // persisted here — enrollment stays pending until the user
                // passes the transcription check, at which point the caller
                // runs `save_generated_recovery_key_metadata`. The server-side
                // backup marker below records a server fact (the ciphertext
                // exists) and therefore lands at accept time.
                if let Ok(mut store) = state_store.try_write() {
                    let configured_backup_id = account_backup_id
                        .as_deref()
                        .unwrap_or(did_backup_id.as_str());
                    crate::components::mark_mls_recovery_backup_configured(
                        &mut store,
                        &actor_for_sidecar,
                        configured_backup_id,
                    );
                }
                if account_backup_id.is_some()
                    && let Some(mut needs_mls_backup) = needs_mls_backup_signal
                {
                    needs_mls_backup.set(false);
                }
                // Best-effort: also back up the encrypted local-plaintext sidecar
                // so a fresh device recovers the author's own content. A failure
                // here must not block the (successful) account-secret backup.
                if account_backup_id.is_some()
                    && let Some(sidecar_json) = sidecar_json
                {
                    let actor = actor_for_sidecar;
                    let device = device_for_sidecar;
                    let _ =
                        with_authed_api(&base_for_sidecar, session_for_sidecar, |api| async move {
                            let secure =
                                crate::secure_key_store::default_secure_key_store("yougen");
                            crate::mls::account_recovery::upload_mls_private_plaintext_backup(
                                &api,
                                secure.as_ref(),
                                &actor,
                                &device,
                                &sidecar_json,
                            )
                            .await
                        })
                        .await;
                }
                if let Ok(mut slot) = status.try_write() {
                    *slot = if account_backup_id.is_some() {
                        "Recovery Key generated; DID recovery and encrypted history are backed up. Write the 24 words down — they are the only way to restore on a new device.".to_owned()
                    } else {
                        "Recovery Key generated and DID recovery backup is on the server. Encrypted content will be backed up to it automatically the first time you use encryption.".to_owned()
                    };
                }
                if let Some(handler) = on_server_configured {
                    handler.call(());
                }
                if let Some(handler) = on_outcome {
                    handler.call(RecoveryKeyBackupOutcome::Established);
                }
            }
            Err(err) => {
                // Fail-closed: nothing was persisted before this point, so a
                // rejection leaves no divergent Recovery Key behind. Classify
                // the failure so the prompt can route an unauthorized device to
                // device-authorization / restore instead of pretending a fresh
                // account recovery root was created.
                let device_unauthorized = crate::api::is_device_not_authorized_error(err.inner());
                if let Ok(mut slot) = status.try_write() {
                    *slot = if device_unauthorized {
                        "This device isn't authorized to set up the account Recovery Key. Authorize it from a device you already use, or restore with your existing 24-word Recovery Key.".to_owned()
                    } else {
                        format!(
                            "Couldn't reach the server to set up recovery (nothing was changed): {}. Try again.",
                            err.display()
                        )
                    };
                }
                if let Some(handler) = on_outcome {
                    handler.call(if device_unauthorized {
                        RecoveryKeyBackupOutcome::DeviceNotAuthorized
                    } else {
                        RecoveryKeyBackupOutcome::Transient
                    });
                }
            }
        }
    });
}
