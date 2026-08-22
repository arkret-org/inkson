//! Custody-confirmed Recovery Key publication and first-backup flow.

use std::sync::atomic::{AtomicBool, Ordering};

use dioxus::prelude::*;

use crate::state::LocalStateStore;
use crate::transport::auth::with_authed_api;

static RECOVERY_KEY_PUBLICATION_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

struct RecoveryKeyPublicationGuard;

impl RecoveryKeyPublicationGuard {
    fn acquire() -> Option<Self> {
        RECOVERY_KEY_PUBLICATION_IN_FLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for RecoveryKeyPublicationGuard {
    fn drop(&mut self) {
        RECOVERY_KEY_PUBLICATION_IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// After the caller has displayed the words and verified the offline copy,
/// publish the active recovery policy, then wrap the account MLS secret for
/// the policy's dedicated HPKE recipient.
/// Outcome of attempting to establish a freshly generated account Recovery Key
/// on the server, reported back to the setup prompt so it can stay fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryKeyBackupOutcome {
    /// Server accepted the recovery policy and account-secret backup. The
    /// caller may now persist public-only local
    /// metadata and clear the already-confirmed plaintext from memory.
    Established,
    /// The server refused because this session device is not an authorized,
    /// verified key-management device (`device_unauthorized`). The generated
    /// key remains only in the caller's in-memory custody-confirmation surface;
    /// it is never persisted or uploaded.
    DeviceUnauthorized,
    /// A transient failure (network / 5xx / not-yet-authenticated). Nothing was
    /// established; the caller may retry without having leaked or persisted a
    /// divergent key.
    Transient,
}

pub(crate) fn upload_recovery_key_account_backup(
    token: Signal<String>,
    principal_id: Signal<String>,
    device_id: Signal<String>,
    state_store: SyncSignal<LocalStateStore>,
    recovery_key: String,
    mut status: Signal<String>,
    on_server_configured: Option<EventHandler<()>>,
    on_outcome: Option<EventHandler<RecoveryKeyBackupOutcome>>,
) {
    let Some(publication_guard) = RecoveryKeyPublicationGuard::acquire() else {
        return;
    };
    let Some(recovery_secret) = crate::recovery_crypto::normalize_recovery_key_input(&recovery_key)
    else {
        return;
    };
    let base = account.server_url.to_string();
    let session = token();
    let actor = principal_id();
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
    let recovery_material_evidence = state_store.read().recovery_material_evidence();
    let governance_state_store = crate::app::runtime_adapter::state_store_handle(state_store);
    let needs_mls_backup_signal = crate::components::try_needs_mls_backup_signal();
    // `tr()` reads the i18n signal out of Dioxus context, which is not
    // available inside the spawned task below — the same constraint
    // documented on `setup::realms::BootstrapProgressStrings`. The status
    // signal carries resolved text (its consumers render it directly), so
    // resolve every template here and move them across the boundary.
    let status_publishing = crate::i18n::tr("recovery.upload.publishing");
    let status_backed_up = crate::i18n::tr("recovery.upload.backed_up");
    let status_policy_active = crate::i18n::tr("recovery.upload.policy_active");
    let status_device_unauthorized = crate::i18n::tr("recovery.upload.device_unauthorized");
    let status_unreachable_tpl = crate::i18n::tr("recovery.upload.unreachable");
    status.set(status_publishing);
    spawn(async move {
        let _publication_guard = publication_guard;
        let actor_for_sidecar = actor.clone();
        let authority_for_sidecar = authority.clone();
        let device_for_sidecar = device.clone();
        let base_for_sidecar = base.clone();
        let session_for_sidecar = session.clone();
        let mut state_store = state_store;
        let result = with_authed_api(&base, session, |api| async move {
            let evidence = recovery_material_evidence.ok_or_else(|| {
                anyhow::anyhow!("frozen PCR authority evidence is required for recovery setup")
            })?;
            if evidence.principal_id != actor_full_id || evidence.device_id.as_str() != device {
                anyhow::bail!("recovery authority evidence does not match the active session");
            }
            crate::recovery_strand::verify_recovery_authority_evidence(&api, &evidence).await?;
            crate::recovery_strand::ensure_principal_bootstrap_governance_checkpoint(
                &api,
                &governance_state_store,
                &evidence.bootstrap_seal,
            )
            .await?;
            crate::recovery_strand::ensure_recovery_policy(
                &api,
                &evidence.principal_id,
                &evidence.device_id,
                &evidence.principal_control_realm_id,
                &recovery_secret,
            )
            .await?;
            let secure = crate::secure_key_store::default_secure_key_store("inkson");
            crate::mls::runtime::load_account_mls_secret(secure.as_ref(), &authority)
                .map_err(|err| anyhow::anyhow!("load account MLS secret before backup: {err}"))?
                .ok_or_else(|| anyhow::anyhow!("account MLS secret recovery is required"))?;
            let account_backup_id = Some(
                crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key(
                    &api,
                    secure.as_ref(),
                    &authority,
                    &actor,
                    &device,
                    &recovery_secret,
                )
                .await?,
            );
            Ok::<_, anyhow::Error>(account_backup_id)
        })
        .await;
        match result {
            Ok(account_backup_id) => {
                // The caller already confirmed cold custody before invoking
                // this function. Only public local metadata and the server fact
                // that ciphertext exists are persisted after acceptance.
                if let Ok(mut store) = state_store.try_write()
                    && let Some(configured_backup_id) = account_backup_id.as_deref()
                {
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
                                crate::secure_key_store::default_secure_key_store("inkson");
                            crate::mls::account_recovery::upload_mls_private_plaintext_backup(
                                &api,
                                secure.as_ref(),
                                &authority_for_sidecar,
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
                        status_backed_up.clone()
                    } else {
                        status_policy_active.clone()
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
                // Fail-closed: no pending Recovery Key was persisted before
                // server acceptance, so a rejection leaves no divergent key
                // behind. Classify
                // the failure so the prompt can route an unauthorized device to
                // device-authorization / restore instead of pretending a fresh
                // account recovery root was created.
                let device_unauthorized =
                    crate::api_error::is_device_not_authorized_error(err.inner());
                if let Ok(mut slot) = status.try_write() {
                    *slot = if device_unauthorized {
                        status_device_unauthorized.clone()
                    } else {
                        crate::i18n::substitute_args(
                            status_unreachable_tpl.clone(),
                            &[("error", err.display().to_string())],
                        )
                    };
                }
                if let Some(handler) = on_outcome {
                    handler.call(if device_unauthorized {
                        RecoveryKeyBackupOutcome::DeviceUnauthorized
                    } else {
                        RecoveryKeyBackupOutcome::Transient
                    });
                }
            }
        }
    });
}
