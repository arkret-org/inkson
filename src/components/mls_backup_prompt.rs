use dioxus::prelude::*;

use crate::recovery_crypto::{RECOVERY_PASSPHRASE_MIN_STRENGTH, estimate_passphrase_strength};
use crate::views::helpers::with_authed_api;

/// One-time account-MLS-secret BACKUP prompt — the mirror of
/// [`crate::components::MlsUnlockPrompt`].
///
/// Mounted once near the app shell and rendered ONLY when `needs_mls_backup`
/// is `true` — which the boot/per-space detection in `App` sets when this
/// account has a LOCAL account MLS secret (encryption has been used) but the
/// server holds NO `mls_account_secret` backup yet. The user picks a recovery
/// passphrase and we call
/// [`crate::mls::account_recovery::upload_mls_account_secret_backup_with_passphrase`]
/// to wrap + upload the account secret so a future fresh browser can recover
/// encrypted history.
#[component]
pub fn MlsBackupPrompt(
    base_url: Signal<String>,
    token: Signal<String>,
    actor_did: Signal<String>,
    device_id: Signal<String>,
    needs_mls_backup: Signal<bool>,
) -> Element {
    let mut passphrase = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut busy = use_signal(|| false);

    if !needs_mls_backup() {
        return rsx! {};
    }

    let pass_now = passphrase();
    let confirm_now = confirm();
    let too_weak =
        !pass_now.is_empty() && estimate_passphrase_strength(&pass_now) < RECOVERY_PASSPHRASE_MIN_STRENGTH;
    let mismatch = !confirm_now.is_empty() && pass_now != confirm_now;
    let can_submit = !pass_now.is_empty()
        && pass_now == confirm_now
        && estimate_passphrase_strength(&pass_now) >= RECOVERY_PASSPHRASE_MIN_STRENGTH;

    let on_backup = move |_| {
        if busy() {
            return;
        }
        let pass = passphrase();
        if pass.is_empty() {
            status.set(crate::i18n::tr("mls_backup.status.enter_passphrase"));
            return;
        }
        if pass != confirm() {
            status.set(crate::i18n::tr("mls_backup.status.mismatch"));
            return;
        }
        if estimate_passphrase_strength(&pass) < RECOVERY_PASSPHRASE_MIN_STRENGTH {
            status.set(crate::i18n::tr("mls_backup.status.too_weak"));
            return;
        }
        let base = base_url();
        let session = token();
        let actor = actor_did();
        let device = device_id();
        let mut needs_mls_backup = needs_mls_backup;
        busy.set(true);
        status.set(crate::i18n::tr("mls_backup.status.uploading"));
        spawn(async move {
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
                    passphrase.set(String::new());
                    confirm.set(String::new());
                    status.set(crate::i18n::tr("mls_backup.status.created"));
                    crate::api::sleep_for(std::time::Duration::from_millis(750)).await;
                    needs_mls_backup.set(false);
                }
                Err(err) => {
                    // Keep the prompt open so the user can retry.
                    status.set(err.display());
                }
            }
        });
    };

    rsx! {
        div {
            class: "event mls-backup-banner",
            "data-testid": "mls-backup-banner",
            role: "region",
            "aria-label": crate::i18n::tr("mls_backup.aria_label"),
            div { class: "event-head",
                strong { {crate::i18n::tr("mls_backup.title")} }
                span { class: "muted", {crate::i18n::tr("mls_backup.subtitle")} }
            }
            div { class: "muted",
                {crate::i18n::tr("mls_backup.description")}
            }
            div { class: "muted", "data-testid": "mls-backup-passphrase-loss-warning",
                strong { {crate::i18n::tr("mls_backup.warning.passphrase_loss")} }
            }
            div { class: "mls-backup-row",
                input {
                    r#type: "password",
                    "data-testid": "mls-backup-passphrase",
                    placeholder: crate::i18n::tr("mls_backup.placeholder"),
                    value: "{passphrase}",
                    disabled: busy(),
                    oninput: move |evt| passphrase.set(evt.value()),
                }
            }
            div { class: "mls-backup-row",
                input {
                    r#type: "password",
                    "data-testid": "mls-backup-confirm",
                    placeholder: crate::i18n::tr("mls_backup.placeholder_confirm"),
                    value: "{confirm}",
                    disabled: busy(),
                    oninput: move |evt| confirm.set(evt.value()),
                }
            }
            if too_weak {
                div { class: "muted", "data-testid": "mls-backup-weak-hint",
                    {crate::i18n::tr("mls_backup.hint.too_weak")}
                }
            }
            if mismatch {
                div { class: "muted", "data-testid": "mls-backup-mismatch-hint",
                    {crate::i18n::tr("mls_backup.hint.mismatch")}
                }
            }
            div { class: "mls-backup-row",
                button {
                    class: "primary",
                    "data-testid": "mls-backup-submit",
                    disabled: busy() || !can_submit,
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
            }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "mls-backup-status", "{status}" }
            }
        }
    }
}
