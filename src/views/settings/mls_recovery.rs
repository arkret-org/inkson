//! X11.1 — persistent "MLS Recovery Key" settings section.
//!
//! The one-time [`crate::components::MlsBackupPrompt`] only surfaces when the
//! boot-time detection effect flips `needs_mls_backup`, whose `detection_key`
//! rarely changes — so users frequently never see it. This section is the
//! RELIABLE entry: it is always reachable under
//! `/settings/encryption`, is NOT gated on
//! `needs_mls_backup`, shows the live backup status, and lets the user
//! generate/replace the MLS recovery key regardless of effect timing.
//!
//! On mount it fetches `list_key_backups` to compute status; the submit path
//! mirrors `MlsBackupPrompt` exactly (account-secret upload + best-effort
//! sidecar upload).

use dioxus::prelude::*;

use crate::recovery_crypto::{
    generate_recovery_key, normalize_recovery_key_input, recovery_key_confirmation_matches,
};
use crate::state::LocalStateStore;
use crate::transport::auth::with_authed_api;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;

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
    /// should generate a recovery key backup.
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

#[allow(clippy::too_many_arguments)]
fn start_recovery_key_generation(
    token: Signal<String>,
    account: crate::config::ActiveAccountContext,
    mut state_store: SyncSignal<LocalStateStore>,
    mut generated_recovery_key: Signal<String>,
    mut generated_recovery_key_confirm: Signal<String>,
    mut action_status: Signal<String>,
    mut busy: Signal<bool>,
    mut copied: Signal<bool>,
    mut status: Signal<MlsRecoveryStatus>,
) {
    if busy() {
        return;
    }
    let recovery_key = match generate_recovery_key() {
        Ok(key) => key,
        Err(err) => {
            action_status.set(format!(
                "{} {err}",
                crate::i18n::tr("mls_backup.status.generate_failed")
            ));
            return;
        }
    };
    let Some(recovery_secret) = normalize_recovery_key_input(&recovery_key) else {
        action_status.set(crate::i18n::tr("mls_backup.status.generate_failed"));
        return;
    };
    let base = account.server_url.to_string();
    let authority = account.authority.clone();
    let session = token();
    let actor = account.full_id().to_string();
    let account_key = account.principal_id().clone();
    let device = account.device_id.to_string();
    let sidecar_json = if state_store.read().private_plaintext_is_empty() {
        None
    } else {
        Some(state_store.read().private_plaintext_snapshot_json())
    };
    busy.set(true);
    copied.set(false);
    generated_recovery_key_confirm.set(String::new());
    action_status.set(crate::i18n::tr("mls_backup.status.uploading"));
    spawn(async move {
        let recovery_key_for_display = recovery_key.clone();
        let actor_for_sidecar = actor.clone();
        let authority_for_sidecar = authority.clone();
        let device_for_sidecar = device.clone();
        let base_for_sidecar = base.clone();
        let session_for_sidecar = session.clone();
        let result = with_authed_api(&base, session, |api| async move {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key(
                &api,
                secure_store.as_ref(),
                &authority,
                &actor,
                &device,
                &recovery_secret,
            )
            .await
        })
        .await;
        busy.set(false);
        match result {
            Ok(backup_id) => {
                crate::components::mark_mls_recovery_backup_configured(
                    &mut state_store.write(),
                    &account_key,
                    &backup_id,
                );
                if let Some(sidecar_json) = sidecar_json {
                    let actor = actor_for_sidecar;
                    let device = device_for_sidecar;
                    let outcome =
                        with_authed_api(&base_for_sidecar, session_for_sidecar, |api| async move {
                            let secure_store =
                                crate::secure_key_store::default_secure_key_store("inkson");
                            crate::mls::account_recovery::upload_mls_private_plaintext_backup(
                                &api,
                                secure_store.as_ref(),
                                &authority_for_sidecar,
                                &actor,
                                &device,
                                &sidecar_json,
                            )
                            .await
                        })
                        .await;
                    let _ = outcome;
                }
                generated_recovery_key.set(recovery_key_for_display);
                generated_recovery_key_confirm.set(String::new());
                action_status.set(crate::i18n::tr("mls_backup.status.created"));
                status.set(MlsRecoveryStatus::BackedUp);
            }
            Err(err) => {
                action_status.set(err.display());
            }
        }
    });
}

#[component]
pub fn SettingsMlsRecoveryPanel(
    token: Signal<String>,
    principal_id: Signal<String>,
    device_id: Signal<String>,
    /// Primary account handle claim, used only to name the recovery-key download file readably.
    account_primary_handle: String,
) -> Element {
    let session = crate::app::SessionContext::get();
    let mut state_store = session.state_store;
    let Some(account) = session.active_account() else {
        return rsx! {};
    };
    let mut status = use_signal(|| MlsRecoveryStatus::Loading);
    let mut generated_recovery_key = use_signal(String::new);
    let mut generated_recovery_key_confirm = use_signal(String::new);
    let mut action_status = use_signal(String::new);
    let busy = use_signal(|| false);
    let mut refill_busy = use_signal(|| false);
    let mut refill_status = use_signal(String::new);
    let mut copied = use_signal(|| false);

    let has_session = !token().trim().is_empty();

    // On mount (and whenever session/actor change): fetch the server backup
    // list and recompute status. Independent of `needs_mls_backup`.
    {
        let account_for_status = account.clone();
        use_resource(move || {
            let account = account_for_status.clone();
            async move {
                let base = account.server_url.to_string();
                let session = token();
                let actor = account.full_id().to_string();
                let account_key = account.principal_id().clone();
                let authority = account.authority.clone();
                if base.trim().is_empty() || session.trim().is_empty() || actor.trim().is_empty() {
                    status.set(MlsRecoveryStatus::NoLocalSecret);
                    return;
                }
                let local_secret = {
                    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                    crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &authority)
                        .ok()
                        .flatten()
                        .is_some()
                };
                let actor_for_fetch = actor.clone();
                match with_authed_api(&base, session, |api| async move {
                    crate::mls::account_recovery::fetch_mls_restore_payload(&api, &actor_for_fetch)
                        .await
                })
                .await
                {
                    Ok(payload) => {
                        let server_backup_body =
                        crate::mls::account_recovery::select_preferred_mls_account_secret_backup(
                            &payload,
                        );
                        if let Some(backup_id) = server_backup_body
                            .as_ref()
                            .and_then(|body| body.get("backup_id"))
                            .and_then(serde_json::Value::as_str)
                        {
                            crate::components::mark_mls_recovery_backup_configured(
                                &mut state_store.write(),
                                &account_key,
                                backup_id,
                            );
                        }
                        let server_backup = server_backup_body.is_some();
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
            }
        });
    }

    let can_submit = has_session && !busy() && generated_recovery_key().trim().is_empty();

    let current_status = status();

    // Submit: mirror `MlsBackupPrompt` — upload the account secret, then
    // best-effort upload the encrypted private-plaintext sidecar.
    let account_for_submit = account.clone();
    let on_submit = move |_| {
        start_recovery_key_generation(
            token,
            account_for_submit.clone(),
            state_store,
            generated_recovery_key,
            generated_recovery_key_confirm,
            action_status,
            busy,
            copied,
            status,
        );
    };

    let account_for_regenerate = account.clone();
    let on_regenerate = move |_| {
        start_recovery_key_generation(
            token,
            account_for_regenerate.clone(),
            state_store,
            generated_recovery_key,
            generated_recovery_key_confirm,
            action_status,
            busy,
            copied,
            status,
        );
    };

    let generated_now = generated_recovery_key();
    let generated_confirm_now = generated_recovery_key_confirm();
    let account_for_refill = account.clone();
    let on_refill = move |_| {
        if refill_busy() {
            return;
        }
        let base = account_for_refill.server_url.to_string();
        let session = token();
        let authority = account_for_refill.authority.clone();
        let device = account_for_refill.device_id.clone();
        refill_busy.set(true);
        refill_status.set(crate::i18n::tr("settings.mls_keypackages.refill_busy"));
        spawn(async move {
            match crate::app::manual_refill_local_mls_key_packages(base, session, authority, device)
                .await
            {
                Ok(count) => refill_status.set(format!(
                    "{} {count}",
                    crate::i18n::tr("settings.mls_keypackages.refill_done")
                )),
                Err(error) => refill_status.set(format!(
                    "{} {error}",
                    crate::i18n::tr("settings.mls_keypackages.refill_failed")
                )),
            }
            refill_busy.set(false);
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
                if !generated_now.trim().is_empty() {
                    div { class: "workflow-form",
                        Label { html_for: "settings-mls-recovery-generated-key",
                            {crate::i18n::tr("mls_backup.generated_key_label")}
                        }
                        Textarea {
                            id: "settings-mls-recovery-generated-key",
                            "data-testid": "settings-mls-recovery-generated-key",
                            rows: "3",
                            readonly: true,
                            value: "{generated_now}",
                        }
                        // Mirror `MlsBackupPrompt`: Copy / Download .txt so the
                        // user captures all 24 words instead of hand-selecting
                        // the textarea (a partial selection silently drops words).
                        div { class: "mls-backup-key-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "settings-mls-recovery-copy-key",
                                onclick: {
                                    let key = generated_now.clone();
                                    move |_| {
                                        crate::components::mls_backup_prompt::copy_text_to_clipboard(&key);
                                        copied.set(true);
                                    }
                                },
                                if copied() {
                                    {crate::i18n::tr("mls_backup.copy_key_done")}
                                } else {
                                    {crate::i18n::tr("mls_backup.copy_key")}
                                }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "settings-mls-recovery-download-key",
                                onclick: {
                                    let key = generated_now.clone();
                                    let primary_handle = account_primary_handle.clone();
                                    move |_| {
                                        let fname =
                                            crate::components::mls_backup_prompt::recovery_key_filename_from_handles(
                                                std::slice::from_ref(&primary_handle),
                                            );
                                        crate::components::mls_backup_prompt::download_text_as_file(&fname, &key);
                                    }
                                },
                                {crate::i18n::tr("mls_backup.download_key")}
                            }
                        }
                        div { class: "form-hint-warn", "data-testid": "settings-mls-recovery-generated-key-warning",
                            {crate::i18n::tr("mls_backup.generated_key_warning")}
                        }
                        Label { html_for: "settings-mls-recovery-confirm-key",
                            {crate::i18n::tr("mls_backup.confirm_key_label")}
                        }
                        Textarea {
                            id: "settings-mls-recovery-confirm-key",
                            "data-testid": "settings-mls-recovery-confirm-key",
                            rows: "3",
                            value: "{generated_confirm_now}",
                            placeholder: crate::i18n::tr("mls_backup.confirm_key_placeholder"),
                            oninput: move |event: FormEvent| generated_recovery_key_confirm.set(event.value()),
                        }
                        div { class: "muted", "data-testid": "settings-mls-recovery-confirm-key-hint",
                            {crate::i18n::tr("mls_backup.confirm_key_hint")}
                        }
                    }
                }
                div { class: "workflow-form",
                    div { class: "actions",
                        if !generated_now.trim().is_empty() {
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "settings-mls-recovery-regenerate",
                                disabled: busy(),
                                onclick: on_regenerate,
                                {crate::i18n::tr("mls_backup.button_regenerate")}
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "settings-mls-recovery-saved",
                                disabled: generated_confirm_now.trim().is_empty(),
                                onclick: move |_| {
                                    if !recovery_key_confirmation_matches(
                                        &generated_recovery_key(),
                                        &generated_recovery_key_confirm(),
                                    ) {
                                        action_status.set(
                                            crate::i18n::tr("mls_backup.status.confirm_mismatch"),
                                        );
                                        return;
                                    }
                                    generated_recovery_key.set(String::new());
                                    generated_recovery_key_confirm.set(String::new());
                                    action_status.set(String::new());
                                    copied.set(false);
                                },
                                {crate::i18n::tr("mls_backup.button_confirm_saved")}
                            }
                        } else {
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "settings-mls-recovery-submit",
                                disabled: !can_submit,
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
            }
            if !action_status().is_empty() {
                div { class: "muted", "data-testid": "settings-mls-recovery-action-status",
                    "{action_status}"
                }
            }
            div { class: "workflow-form", "data-testid": "settings-mls-keypackages-refill",
                div { class: "muted",
                    {crate::i18n::tr("settings.mls_keypackages.refill_description")}
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "settings-mls-keypackages-refill-button",
                        disabled: !has_session || refill_busy(),
                        onclick: on_refill,
                        {crate::i18n::tr("settings.mls_keypackages.refill_button")}
                    }
                }
                if !refill_status().is_empty() {
                    div { class: "muted", "data-testid": "settings-mls-keypackages-refill-status",
                        "{refill_status}"
                    }
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
        assert_eq!(
            resolve_status(false, false),
            MlsRecoveryStatus::NoLocalSecret
        );
    }

    #[test]
    fn badge_values_are_stable() {
        assert_eq!(MlsRecoveryStatus::Loading.badge(), "loading");
        assert_eq!(MlsRecoveryStatus::BackedUp.badge(), "backed-up");
        assert_eq!(MlsRecoveryStatus::NotBackedUp.badge(), "not-backed-up");
        assert_eq!(MlsRecoveryStatus::NoLocalSecret.badge(), "no-local-secret");
    }
}
