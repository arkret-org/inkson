//! X11.1 — persistent "MLS Recovery Passphrase" settings section.
//!
//! The one-time [`crate::components::MlsBackupPrompt`] only surfaces when the
//! boot-time detection effect flips `needs_mls_backup`, whose `detection_key`
//! rarely changes — so users frequently never see it. This section is the
//! RELIABLE entry: it is always reachable under
//! `/settings/encryption` (Security & recovery), is NOT gated on
//! `needs_mls_backup`, shows the live backup status, and lets the user
//! set/replace the MLS recovery passphrase regardless of effect timing.
//!
//! On mount it fetches `list_key_backups` to compute status; the submit path
//! mirrors `MlsBackupPrompt` exactly (account-secret upload + best-effort
//! sidecar upload).

use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::recovery_crypto::{RECOVERY_PASSPHRASE_MIN_STRENGTH, estimate_passphrase_strength};
use crate::views::helpers::with_authed_api;

/// Resolved backup status for the section header / status line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MlsRecoveryStatus {
    /// Still loading the server backup list.
    Loading,
    /// No local account secret — encryption hasn't been used yet, so there's
    /// nothing to back up.
    NoLocalSecret,
    /// Server already holds an `mls_account_secret` backup.
    BackedUp,
    /// Local account secret exists but the server has no backup → the user
    /// should set a recovery passphrase.
    NotBackedUp,
}

impl MlsRecoveryStatus {
    /// i18n key for the human-readable status line.
    fn i18n_key(self) -> &'static str {
        match self {
            Self::Loading => "settings.mls_recovery.status.loading",
            Self::NoLocalSecret => "settings.mls_recovery.status.no_local_secret",
            Self::BackedUp => "settings.mls_recovery.status.backed_up",
            Self::NotBackedUp => "settings.mls_recovery.status.not_backed_up",
        }
    }

    /// `data-testid` status badge value (stable across locales for e2e).
    fn badge(self) -> &'static str {
        match self {
            Self::Loading => "loading",
            Self::NoLocalSecret => "no-local-secret",
            Self::BackedUp => "backed-up",
            Self::NotBackedUp => "not-backed-up",
        }
    }
}

/// Compute the backup status from a fetched `list_key_backups` payload + the
/// local account-secret presence. Pure so it can be unit-tested without a
/// live session.
fn resolve_status(server_backup: bool, local_secret: bool) -> MlsRecoveryStatus {
    if server_backup {
        MlsRecoveryStatus::BackedUp
    } else if local_secret {
        MlsRecoveryStatus::NotBackedUp
    } else {
        MlsRecoveryStatus::NoLocalSecret
    }
}

#[component]
pub fn SettingsMlsRecoveryPanel(
    base_url: Signal<String>,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut status = use_signal(|| MlsRecoveryStatus::Loading);
    let mut passphrase = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut action_status = use_signal(String::new);
    let mut busy = use_signal(|| false);

    let has_session = !token().trim().is_empty();

    // On mount (and whenever session/actor change): fetch the server backup
    // list and recompute status. Independent of `needs_mls_backup`.
    {
        use_resource(move || async move {
            let base = base_url();
            let session = token();
            let actor = account_did();
            if base.trim().is_empty() || session.trim().is_empty() || actor.trim().is_empty() {
                status.set(MlsRecoveryStatus::NoLocalSecret);
                return;
            }
            let local_secret = {
                let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
                crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &actor)
                    .ok()
                    .flatten()
                    .is_some()
            };
            match with_authed_api(&base, session, |api| async move {
                crate::mls::account_recovery::fetch_mls_restore_payload(&api).await
            })
            .await
            {
                Ok(payload) => {
                    let server_backup =
                        crate::mls::account_recovery::select_mls_account_secret_backup(&payload)
                            .is_some();
                    status.set(resolve_status(server_backup, local_secret));
                }
                Err(err) => {
                    // Couldn't reach the server — fall back to the local-only
                    // signal so the user still gets an actionable view.
                    action_status.set(err.display());
                    status.set(if local_secret {
                        MlsRecoveryStatus::NotBackedUp
                    } else {
                        MlsRecoveryStatus::NoLocalSecret
                    });
                }
            }
        });
    }

    let pass_now = passphrase();
    let confirm_now = confirm();
    let too_weak = !pass_now.is_empty()
        && estimate_passphrase_strength(&pass_now) < RECOVERY_PASSPHRASE_MIN_STRENGTH;
    let mismatch = !confirm_now.is_empty() && pass_now != confirm_now;
    let can_submit = has_session
        && !pass_now.is_empty()
        && pass_now == confirm_now
        && estimate_passphrase_strength(&pass_now) >= RECOVERY_PASSPHRASE_MIN_STRENGTH;

    let current_status = status();
    let strength = estimate_passphrase_strength(&pass_now);

    // Submit: mirror `MlsBackupPrompt` — upload the account secret, then
    // best-effort upload the encrypted private-plaintext sidecar.
    let on_submit = move |_| {
        if busy() {
            return;
        }
        let pass = passphrase();
        if pass.is_empty() {
            action_status.set(crate::i18n::tr("mls_backup.status.enter_passphrase"));
            return;
        }
        if pass != confirm() {
            action_status.set(crate::i18n::tr("mls_backup.status.mismatch"));
            return;
        }
        if estimate_passphrase_strength(&pass) < RECOVERY_PASSPHRASE_MIN_STRENGTH {
            action_status.set(crate::i18n::tr("mls_backup.status.too_weak"));
            return;
        }
        let base = base_url();
        let session = token();
        let actor = account_did();
        let device = device_id();
        // Snapshot the sidecar synchronously before any await (don't borrow the
        // store across the network calls).
        let sidecar_json = if state_store.read().private_plaintext_is_empty() {
            None
        } else {
            Some(state_store.read().private_plaintext_snapshot_json())
        };
        busy.set(true);
        action_status.set(crate::i18n::tr("mls_backup.status.uploading"));
        spawn(async move {
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
                    pass.as_bytes(),
                )
                .await
            })
            .await;
            busy.set(false);
            match result {
                Ok(_backup_id) => {
                    // Best-effort sidecar upload (account secret already
                    // succeeded; sidecar failure must not block success).
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
                        let _ = outcome;
                    }
                    passphrase.set(String::new());
                    confirm.set(String::new());
                    action_status.set(crate::i18n::tr("mls_backup.status.created"));
                    status.set(MlsRecoveryStatus::BackedUp);
                }
                Err(err) => {
                    action_status.set(err.display());
                }
            }
        });
    };

    rsx! {
        div { class: "event", "data-testid": "settings-mls-recovery",
            div { class: "event-head",
                span { {crate::i18n::tr("settings.mls_recovery.title")} }
                span {
                    "data-testid": "settings-mls-recovery-status-badge",
                    "{current_status.badge()}"
                }
            }
            div { class: "muted", "data-testid": "settings-mls-recovery-status",
                {crate::i18n::tr(current_status.i18n_key())}
            }
            div { class: "muted", "data-testid": "settings-mls-recovery-warning",
                {crate::i18n::tr("mls_backup.warning.passphrase_loss")}
            }

            // Hide the set/replace form when there's nothing to back up yet —
            // the account secret only exists after the first encrypted write.
            if current_status != MlsRecoveryStatus::NoLocalSecret {
                div { class: "workflow-form",
                    label { r#for: "settings-mls-recovery-passphrase",
                        {crate::i18n::tr("settings.mls_recovery.passphrase_label")}
                    }
                    input {
                        id: "settings-mls-recovery-passphrase",
                        "data-testid": "settings-mls-recovery-passphrase",
                        r#type: "password",
                        autocomplete: "new-password",
                        placeholder: crate::i18n::tr("mls_backup.placeholder"),
                        value: "{passphrase}",
                        disabled: busy() || !has_session,
                        oninput: move |evt| passphrase.set(evt.value()),
                    }
                    input {
                        "data-testid": "settings-mls-recovery-confirm",
                        r#type: "password",
                        autocomplete: "new-password",
                        placeholder: crate::i18n::tr("mls_backup.placeholder_confirm"),
                        value: "{confirm}",
                        disabled: busy() || !has_session,
                        oninput: move |evt| confirm.set(evt.value()),
                    }
                    div {
                        class: if too_weak { "form-hint-warn" } else { "muted" },
                        "data-testid": "settings-mls-recovery-strength",
                        {format!(
                            "{} ({strength}/5). {}",
                            crate::i18n::tr("settings.mls_recovery.strength_prefix"),
                            crate::i18n::tr("settings.mls_recovery.strength_min"),
                        )}
                    }
                    if too_weak {
                        div { class: "form-hint-warn", "data-testid": "settings-mls-recovery-weak-hint",
                            {crate::i18n::tr("mls_backup.hint.too_weak")}
                        }
                    }
                    if mismatch {
                        div { class: "form-hint-warn", "data-testid": "settings-mls-recovery-mismatch-hint",
                            {crate::i18n::tr("mls_backup.hint.mismatch")}
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "settings-mls-recovery-submit",
                            disabled: busy() || !can_submit,
                            onclick: on_submit,
                            if busy() {
                                {crate::i18n::tr("mls_backup.button_busy")}
                            } else {
                                {crate::i18n::tr("settings.mls_recovery.submit")}
                            }
                        }
                    }
                }
            }
            if !action_status().is_empty() {
                div { class: "muted", "data-testid": "settings-mls-recovery-action-status",
                    "{action_status}"
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_backed_up_when_server_has_backup() {
        assert_eq!(resolve_status(true, true), MlsRecoveryStatus::BackedUp);
        // Server backup wins even if the local secret read failed.
        assert_eq!(resolve_status(true, false), MlsRecoveryStatus::BackedUp);
    }

    #[test]
    fn status_not_backed_up_when_local_secret_but_no_server() {
        assert_eq!(resolve_status(false, true), MlsRecoveryStatus::NotBackedUp);
    }

    #[test]
    fn status_no_local_secret_when_nothing_local() {
        assert_eq!(resolve_status(false, false), MlsRecoveryStatus::NoLocalSecret);
    }

    #[test]
    fn badge_values_are_stable() {
        assert_eq!(MlsRecoveryStatus::Loading.badge(), "loading");
        assert_eq!(MlsRecoveryStatus::BackedUp.badge(), "backed-up");
        assert_eq!(MlsRecoveryStatus::NotBackedUp.badge(), "not-backed-up");
        assert_eq!(MlsRecoveryStatus::NoLocalSecret.badge(), "no-local-secret");
    }
}
