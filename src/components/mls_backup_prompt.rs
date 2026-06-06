use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::recovery_crypto::{generate_recovery_key, normalize_recovery_key_input};
use crate::views::helpers::with_authed_api;

const MLS_RECOVERY_BACKUP_STATE_KEY: &str = "mls.recovery_backup.v1";

pub(crate) fn mls_recovery_backup_configured(
    state_store: &LocalStateStore,
    actor_did: &str,
) -> bool {
    if actor_did.trim().is_empty() {
        return false;
    }
    state_store
        .load_private_data(actor_did, MLS_RECOVERY_BACKUP_STATE_KEY)
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|value| {
            value
                .get("backup_id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .map(str::to_owned)
        })
        .is_some_and(|backup_id| !backup_id.is_empty())
}

pub(crate) fn mark_mls_recovery_backup_configured(
    state_store: &mut LocalStateStore,
    actor_did: &str,
    backup_id: &str,
) {
    if actor_did.trim().is_empty() || backup_id.trim().is_empty() {
        return;
    }
    let payload = serde_json::json!({
        "schema_version": 1,
        "backup_id": backup_id,
        "configured_at": chrono::Utc::now().to_rfc3339(),
    });
    state_store.save_private_data(
        actor_did,
        MLS_RECOVERY_BACKUP_STATE_KEY,
        payload.to_string(),
    );
}

/// X11.2 — context-provided handle to the app-root `needs_mls_backup`
/// `Signal<bool>` so deep encrypted-write success paths (kanban card detail
/// update, chat secure send) can flip the backup prompt on directly, WITHOUT
/// relying on the fragile boot-time detection effect (whose `detection_key`
/// rarely flips). Provided once at the app root; consumed via
/// [`try_needs_mls_backup_signal`] from free functions / event handlers that
/// run inside a Dioxus scope.
///
/// Newtype-wrapped so the context lookup can't collide with any other bare
/// `Signal<bool>` a future view might provide.
#[derive(Clone, Copy)]
pub struct MlsBackupSignal(pub Signal<bool>);

/// Best-effort: read the context-provided `needs_mls_backup` signal. Returns
/// `None` when no provider is mounted (e.g. unit tests) so callers can stay
/// non-fatal.
pub fn try_needs_mls_backup_signal() -> Option<Signal<bool>> {
    try_consume_context::<MlsBackupSignal>().map(|wrap| wrap.0)
}

/// X11.2 — shared first-write trigger. After a successful ENCRYPTED write,
/// the caller spawns this: if the server holds NO `mls_account_secret`
/// backup yet AND a local account secret exists, flip `needs_mls_backup` on
/// so [`MlsBackupPrompt`] surfaces promptly. Best-effort and self-contained:
/// swallows every error and never blocks the write path. Reliable because it
/// re-evaluates server+local state on each encrypted write rather than
/// depending on the boot detection effect's `detection_key`.
pub async fn maybe_flag_mls_backup_after_encrypted_write(
    base_url: String,
    token: String,
    actor_did: String,
    mut needs_mls_backup: Signal<bool>,
) {
    if base_url.trim().is_empty() || token.trim().is_empty() || actor_did.trim().is_empty() {
        return;
    }
    // Local account secret must exist (encryption has been used) — otherwise
    // there's nothing to back up yet.
    let has_local_secret = {
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &actor_did)
            .map(|secret| secret.is_some())
            .unwrap_or(false)
    };
    if !has_local_secret {
        return;
    }
    // Surface the prompt as soon as the local account secret exists. The
    // server probe below will close it again if a recovery-key backup is
    // already present. This avoids a silent window after creating an encrypted
    // Realm where the app has recoverable material locally but the async
    // backup-list check has not completed yet.
    needs_mls_backup.set(true);
    // Server must NOT already hold an `mls_account_secret` backup. (When it
    // does, the restore/unlock path owns the flow — backup and restore are
    // mutually exclusive by this exact check, so we can't double-prompt.)
    let payload = match with_authed_api(&base_url, token, |api| async move {
        crate::mls::account_recovery::fetch_mls_restore_payload(&api).await
    })
    .await
    {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(
                error = %err.display(),
                "MLS backup detection could not list key backups after encrypted write"
            );
            needs_mls_backup.set(true);
            return;
        }
    };
    if crate::mls::account_recovery::select_mls_account_secret_backup(&payload).is_some() {
        needs_mls_backup.set(false);
        return;
    }
    needs_mls_backup.set(true);
}

/// One-time account-MLS-secret BACKUP prompt — the mirror of
/// [`crate::components::MlsUnlockPrompt`].
///
/// Mounted once near the app shell and rendered ONLY when `needs_mls_backup`
/// is `true` — which the boot/per-Realm detection in `App` sets when this
/// account has a LOCAL account MLS secret (encryption has been used) but the
/// server holds NO `mls_account_secret` backup yet. The client generates a
/// high-entropy recovery key and we call
/// [`crate::mls::account_recovery::upload_mls_account_secret_backup_with_passphrase`]
/// to wrap + upload the account secret so a future fresh browser can recover
/// encrypted history. The wire recipient method remains spec-conformant
/// `secret_storage` + `passphrase_kdf`; the user-facing flow does not ask the
/// user to invent or confirm a passphrase.
#[component]
pub fn MlsBackupPrompt(
    base_url: Signal<String>,
    token: Signal<String>,
    actor_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
    needs_mls_backup: Signal<bool>,
) -> Element {
    let mut generated_recovery_key = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut busy = use_signal(|| false);

    if !needs_mls_backup() {
        return rsx! {};
    }

    let can_submit = !busy()
        && generated_recovery_key().trim().is_empty()
        && !base_url().trim().is_empty()
        && !token().trim().is_empty()
        && !actor_did().trim().is_empty();

    let on_backup = move |_| {
        if busy() {
            return;
        }
        let recovery_key = match generate_recovery_key() {
            Ok(key) => key,
            Err(err) => {
                status.set(format!(
                    "{} {err}",
                    crate::i18n::tr("mls_backup.status.generate_failed")
                ));
                return;
            }
        };
        let recovery_secret = normalize_recovery_key_input(&recovery_key)
            .expect("generated recovery key is valid BIP-39");
        let base = base_url();
        let session = token();
        let actor = actor_did();
        let device = device_id();
        let mut state_store_for_marker = state_store;
        // X5.3 — snapshot the local-plaintext sidecar so we can also back it up
        // cross-device after the account secret upload succeeds. Read it here
        // (synchronously, before the spawn) so we don't borrow the store across
        // the network awaits.
        let sidecar_json = if state_store.read().private_plaintext_is_empty() {
            None
        } else {
            Some(state_store.read().private_plaintext_snapshot_json())
        };
        busy.set(true);
        status.set(crate::i18n::tr("mls_backup.status.uploading"));
        spawn(async move {
            let recovery_key_for_display = recovery_key.clone();
            let actor_for_sidecar = actor.clone();
            let device_for_sidecar = device.clone();
            let base_for_sidecar = base.clone();
            let session_for_sidecar = session.clone();
            let result = with_authed_api(&base, session, |api| async move {
                let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
                crate::mls::account_recovery::upload_mls_account_secret_backup_with_passphrase(
                    &api,
                    secure_store.as_ref(),
                    &actor,
                    &device,
                    recovery_secret.as_bytes(),
                )
                .await
            })
            .await;
            busy.set(false);
            match result {
                Ok(backup_id) => {
                    mark_mls_recovery_backup_configured(
                        &mut state_store_for_marker.write(),
                        &actor_for_sidecar,
                        &backup_id,
                    );
                    // X5.3 — best-effort: also back up the encrypted sidecar so a
                    // fresh browser recovers the author's own content. Failure
                    // only logs (the account secret backup already succeeded).
                    if let Some(sidecar_json) = sidecar_json {
                        let actor = actor_for_sidecar;
                        let device = device_for_sidecar;
                        let outcome = with_authed_api(
                            &base_for_sidecar,
                            session_for_sidecar,
                            |api| async move {
                                let secure_store =
                                    crate::secure_key_store::default_secure_key_store("yougen");
                                crate::mls::account_recovery::upload_mls_private_plaintext_backup(
                                    &api,
                                    secure_store.as_ref(),
                                    &actor,
                                    &device,
                                    &sidecar_json,
                                )
                                .await
                            },
                        )
                        .await;
                        // Best-effort: the account secret backup already
                        // succeeded, so a sidecar failure must not block the
                        // success path. Swallow it (the next encrypted write or
                        // the kanban write-path trigger will retry the upload).
                        let _ = outcome;
                    }
                    generated_recovery_key.set(recovery_key_for_display);
                    status.set(crate::i18n::tr("mls_backup.status.created"));
                }
                Err(err) => {
                    // Keep the prompt open so the user can retry.
                    status.set(err.display());
                }
            }
        });
    };

    let generated_now = generated_recovery_key();

    rsx! {
        div {
            class: "modal-overlay mls-recovery-modal-overlay",
            "data-testid": "mls-backup-modal",
            div {
                class: "modal event mls-recovery-modal mls-backup-banner",
                "data-testid": "mls-backup-banner",
                role: "dialog",
                "aria-modal": "true",
                "aria-labelledby": "mls-backup-title",
                "aria-label": crate::i18n::tr("mls_backup.aria_label"),
                div { class: "modal-head event-head",
                    h3 { id: "mls-backup-title", {crate::i18n::tr("mls_backup.title")} }
                    span { class: "muted", {crate::i18n::tr("mls_backup.subtitle")} }
                }
                div { class: "modal-body mls-recovery-modal-body",
                    div { class: "muted",
                        {crate::i18n::tr("mls_backup.description")}
                    }
                    div { class: "muted", "data-testid": "mls-backup-passphrase-loss-warning",
                        strong { {crate::i18n::tr("mls_backup.warning.passphrase_loss")} }
                    }
                    if !generated_now.trim().is_empty() {
                        div { class: "workflow-form",
                            label { r#for: "mls-backup-generated-key",
                                {crate::i18n::tr("mls_backup.generated_key_label")}
                            }
                            textarea {
                                id: "mls-backup-generated-key",
                                "data-testid": "mls-backup-generated-key",
                                rows: "3",
                                readonly: true,
                                value: "{generated_now}",
                            }
                            div { class: "form-hint-warn", "data-testid": "mls-backup-generated-key-warning",
                                {crate::i18n::tr("mls_backup.generated_key_warning")}
                            }
                        }
                    }
                    if !status().is_empty() {
                        div { class: "muted", "data-testid": "mls-backup-status", "{status}" }
                    }
                }
                div { class: "modal-foot mls-backup-row",
                    if generated_now.trim().is_empty() {
                        button {
                            class: "primary",
                            "data-testid": "mls-backup-submit",
                            disabled: !can_submit,
                            onclick: on_backup,
                            if busy() {
                                {crate::i18n::tr("mls_backup.button_busy")}
                            } else {
                                {crate::i18n::tr("mls_backup.button_idle")}
                            }
                        }
                        button {
                            class: "secondary",
                            "data-testid": "mls-backup-dismiss",
                            disabled: busy(),
                            onclick: move |_| needs_mls_backup.set(false),
                            {crate::i18n::tr("mls_backup.button_dismiss")}
                        }
                    } else {
                        button {
                            class: "primary",
                            "data-testid": "mls-backup-saved",
                            onclick: move |_| {
                                generated_recovery_key.set(String::new());
                                needs_mls_backup.set(false);
                            },
                            {crate::i18n::tr("mls_backup.button_saved")}
                        }
                    }
                }
            }
        }
    }
}
