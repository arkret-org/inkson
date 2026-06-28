use std::future::Future;
use std::time::Duration;

use dioxus::prelude::*;
use dioxus_router::Link;

use super::UiIcon;
use crate::local_state::LocalStateStore;
use crate::recovery_crypto::normalize_recovery_key_input;
use crate::routes::Route;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::views::helpers::{ApiCallError, with_authed_api};

const MLS_UNLOCK_FETCH_TIMEOUT: Duration = Duration::from_secs(20);

// Recovery tasks can finish after the prompt scope is gone; dropped signals panic on `set()`.
fn try_set_signal<T: 'static>(mut signal: Signal<T>, value: T) {
    if let Ok(mut slot) = signal.try_write() {
        *slot = value;
    }
}

fn try_set_status(mut status: Signal<String>, value: impl Into<String>) {
    if let Ok(mut slot) = status.try_write() {
        *slot = value.into();
    }
}

async fn mls_unlock_fetch_with_timeout<T, F>(future: F) -> Result<T, ApiCallError>
where
    F: Future<Output = Result<T, ApiCallError>>,
{
    tokio::select! {
        result = future => result,
        _ = crate::api::sleep_for(MLS_UNLOCK_FETCH_TIMEOUT) => Err(ApiCallError::Failed(anyhow::anyhow!(
            "MLS unlock timed out while fetching recovery material"
        ))),
    }
}

/// Account-MLS-secret auto-unlock prompt (step 3 of the recovery strand).
///
/// Mounted once near the app shell and rendered ONLY when `needs_mls_unlock`
/// is `true` — which the boot-time detection in `App` sets when this device
/// is missing usable local MLS history and the server holds an
/// `mls_account_secret` backup. The user supplies their recovery key
/// and we call
/// [`crate::mls::account_recovery::restore_mls_history_with_recovery_key_from_payload`].
#[component]
pub fn MlsUnlockPrompt(
    base_url: Signal<String>,
    token: Signal<String>,
    actor_id: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
    needs_mls_unlock: Signal<bool>,
    restore_payload_cache: Signal<Option<serde_json::Value>>,
) -> Element {
    let mut passphrase = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut dismissed = use_signal(|| false);
    let mut recovery_key_open = use_signal(|| false);

    {
        let mut dismissed = dismissed;
        let mut recovery_key_open = recovery_key_open;
        use_effect(move || {
            if !needs_mls_unlock() {
                dismissed.set(false);
                recovery_key_open.set(false);
            }
        });
    }

    if !needs_mls_unlock() {
        return rsx! {};
    }

    if dismissed() {
        return rsx! {
            Button {
                variant: ButtonVariant::Primary,
                size: ButtonSize::IconSm,
                r#type: "button",
                class: "btn mls-unlock-reopen-button",
                "data-testid": "mls-unlock-reopen",
                title: crate::i18n::tr("mls_unlock.reopen"),
                "aria-label": crate::i18n::tr("mls_unlock.reopen"),
                onclick: move |_| dismissed.set(false),
                UiIcon { name: "unlock" }
            }
        };
    }

    let on_unlock = move |_| {
        if busy() {
            return;
        }
        let raw_pass = passphrase();
        if raw_pass.trim().is_empty() {
            status.set(crate::i18n::tr("mls_unlock.status.enter_passphrase"));
            return;
        }
        let Some(pass) = normalize_recovery_key_input(&raw_pass) else {
            status.set(crate::i18n::tr("mls_unlock.status.invalid_recovery_key"));
            return;
        };
        let base = base_url();
        let session = token();
        let actor = actor_id();
        let device = device_id();
        let mut state_store = state_store;
        let needs_mls_unlock = needs_mls_unlock;
        let restore_payload_cache = restore_payload_cache;
        busy.set(true);
        status.set(crate::i18n::tr("mls_unlock.status.fetching"));
        spawn(async move {
            tracing::warn!(
                target: "mls_unlock",
                %actor,
                %device,
                "MLS unlock: starting recovery-material fetch"
            );
            let fetch_actor = actor.clone();
            let fetch_device = device.clone();
            // SEC-05: fetch the restore payload AND the actor's currently-accepted
            // recovery policy in the same authed session, so the HPKE account-secret
            // backup's `recovery_policy_ref` can be verified before import.
            let payload_result =
                mls_unlock_fetch_with_timeout(with_authed_api(&base, session, |api| async move {
                    let payload =
                        crate::mls::account_recovery::fetch_mls_restore_payload_with_unlock_proof(
                            &api,
                            &fetch_actor,
                            &fetch_device,
                        )
                        .await?;
                    let active_policy =
                        crate::recovery_strand::fetch_active_recovery_policy(&api).await?;
                    Ok::<_, anyhow::Error>((payload, active_policy))
                }))
                .await;
            let result = match payload_result {
                Ok((payload, active_policy)) => {
                    let history_count =
                        crate::mls::account_recovery::select_mls_history_backups(&payload).len();
                    try_set_signal(restore_payload_cache, Some(payload.clone()));
                    tracing::warn!(
                        target: "mls_unlock",
                        history_count,
                        has_active_policy = active_policy.is_some(),
                        "MLS unlock: recovery material fetched"
                    );
                    try_set_status(
                        status,
                        format!(
                            "{} {} {}",
                            crate::i18n::tr("mls_unlock.status.restoring_prefix"),
                            history_count,
                            crate::i18n::tr("mls_unlock.status.restoring_suffix")
                        ),
                    );
                    crate::api::sleep_for(std::time::Duration::from_millis(16)).await;
                    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
                    match state_store.try_write() {
                        Ok(mut store) => {
                            tracing::warn!(
                                target: "mls_unlock",
                                history_count,
                                "MLS unlock: starting local restore"
                            );
                            let restore_result = crate::hpke_backup::derive_recovery_keypair_from_recovery_key(&pass)
                                .map_err(|err| anyhow::anyhow!("derive recovery key: {err}"))
                                .and_then(|(recovery_private_key, _)| {
                                    let expected_policy = active_policy.as_ref().map(|policy| {
                                        (policy.policy_id.as_str(), policy.policy_version)
                                    });
                                    crate::mls::account_recovery::restore_mls_history_with_recovery_key_from_payload(
                                        &payload,
                                        &mut store,
                                        secure_store.as_ref(),
                                        &actor,
                                        &device,
                                        &recovery_private_key,
                                            expected_policy,
                                        )
                                })
                                .map_err(ApiCallError::Failed);
                            tracing::warn!(
                                target: "mls_unlock",
                                success = restore_result.is_ok(),
                                "MLS unlock: local restore finished"
                            );
                            restore_result
                        }
                        Err(_) => Err(ApiCallError::Failed(anyhow::anyhow!(
                            "recovery prompt closed before restore completed"
                        ))),
                    }
                }
                Err(err) => Err(err),
            };
            try_set_signal(busy, false);
            match result {
                Ok(report) => {
                    if let Some(err) = report.first_error {
                        // Some backups failed even though the call returned Ok —
                        // keep the prompt open so the user can retry.
                        try_set_status(
                            status,
                            format!(
                                "{} {} {}; {} {}: {err}",
                                crate::i18n::tr("mls_unlock.status.restored_prefix"),
                                report.restored,
                                crate::i18n::tr("mls_unlock.status.restored_suffix"),
                                report.failed,
                                crate::i18n::tr("mls_unlock.status.failed_suffix")
                            ),
                        );
                    } else {
                        let restored_status = format!(
                            "{} {} {}",
                            crate::i18n::tr("mls_unlock.status.restored_prefix"),
                            report.restored,
                            crate::i18n::tr("mls_unlock.status.restored_suffix")
                        );
                        try_set_signal(passphrase, String::new());
                        try_set_status(status, restored_status);
                        crate::api::sleep_for(std::time::Duration::from_millis(750)).await;
                        try_set_signal(needs_mls_unlock, false);
                    }
                }
                Err(err) => {
                    // Wrong passphrase / network: keep prompt open, surface reason.
                    try_set_status(status, err.display());
                }
            }
        });
    };

    rsx! {
        Dialog {
            open: true,
            on_open_change: move |open: bool| {
                if !open {
                    dismissed.set(true);
                }
            },
            "data-testid": "mls-unlock-modal",
            "aria-labelledby": "mls-unlock-title",
            "aria-label": crate::i18n::tr("mls_unlock.aria_label"),
            div {
                class: "modal event mls-recovery-modal mls-unlock-banner",
                "data-testid": "mls-unlock-banner",
                role: "dialog",
                "aria-modal": "true",
                div { class: "modal-head event-head",
                    h3 { id: "mls-unlock-title", {crate::i18n::tr("mls_unlock.title")} }
                    span { class: "muted", {crate::i18n::tr("mls_unlock.subtitle")} }
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::IconSm,
                        r#type: "button",
                        class: "btn close",
                        "data-testid": "mls-unlock-dismiss",
                        title: crate::i18n::tr("mls_unlock.dismiss"),
                        "aria-label": crate::i18n::tr("mls_unlock.dismiss"),
                        disabled: busy(),
                        onclick: move |_| dismissed.set(true),
                        UiIcon { name: "x" }
                    }
                }
                div { class: "modal-body mls-recovery-modal-body",
                    div { class: "muted",
                        {crate::i18n::tr("mls_unlock.description")}
                    }
                    div {
                        class: "mls-device-authorization-path",
                        "data-testid": "mls-device-authorization-path",
                        div {
                            class: "mls-device-authorization-step",
                            strong { {crate::i18n::tr("mls_unlock.approve_step_existing_title")} }
                            span { {crate::i18n::tr("mls_unlock.approve_step_existing_body")} }
                        }
                        div {
                            class: "mls-device-authorization-step",
                            strong { {crate::i18n::tr("mls_unlock.approve_step_new_title")} }
                            span { {crate::i18n::tr("mls_unlock.approve_step_new_body")} }
                        }
                    }
                    if busy() {
                        div {
                            class: "muted",
                            "data-testid": "mls-unlock-loading",
                            role: "status",
                            {crate::i18n::tr("mls_unlock.loading_hint")}
                        }
                    }
                    if !status().is_empty() {
                        div { class: "muted", "data-testid": "mls-unlock-status", "{status}" }
                    }
                }
                div { class: "modal-foot mls-unlock-row",
                    Link {
                        class: "primary",
                        "data-testid": "mls-unlock-open-pairing",
                        to: Route::SettingsDevicesPair,
                        onclick: move |_| dismissed.set(true),
                        {crate::i18n::tr("mls_unlock.open_pairing")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "mls-unlock-show-recovery-key",
                        disabled: busy(),
                        onclick: move |_| recovery_key_open.set(!recovery_key_open()),
                        if recovery_key_open() {
                            {crate::i18n::tr("mls_unlock.hide_recovery_key")}
                        } else {
                            {crate::i18n::tr("mls_unlock.show_recovery_key")}
                        }
                    }
                }
                if recovery_key_open() {
                    div { class: "modal-foot mls-unlock-row mls-unlock-recovery-row",
                        div { class: "muted mls-unlock-fallback-note",
                            {crate::i18n::tr("mls_unlock.recovery_fallback_hint")}
                        }
                        Input {
                            r#type: "password",
                            "data-testid": "mls-unlock-passphrase",
                            placeholder: crate::i18n::tr("mls_unlock.placeholder"),
                            value: "{passphrase}",
                            disabled: busy(),
                            oninput: move |event: FormEvent| passphrase.set(event.value()),
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "mls-unlock-submit",
                            disabled: busy(),
                            onclick: on_unlock,
                            if busy() {
                                {crate::i18n::tr("mls_unlock.button_busy")}
                            } else {
                                {crate::i18n::tr("mls_unlock.button_idle")}
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Fresh-device recovery diagnostic shown when encrypted Realm/history exists
/// but this account has no recovery-key-backed `mls_account_secret` backup on
/// the server. In that state `MlsUnlockPrompt` cannot ask for a recovery key
/// because there is no account-secret backup to open, so the app must tell the
/// user to create the recovery backup from an existing unlocked device instead
/// of silently rendering empty encrypted surfaces.
#[component]
pub fn MlsRecoverySetupMissingBanner(
    mut needs_mls_recovery_setup: Signal<bool>,
    actor_id: Signal<String>,
) -> Element {
    if !needs_mls_recovery_setup() {
        return rsx! {};
    }

    let actor = actor_id();
    if !actor.trim().is_empty() {
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        if matches!(
            crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), actor.trim()),
            Ok(Some(_))
        ) {
            return rsx! {};
        }
    }

    rsx! {
        Dialog {
            open: true,
            on_open_change: move |open: bool| {
                if !open {
                    needs_mls_recovery_setup.set(false);
                }
            },
            "data-testid": "mls-recovery-missing-modal",
            "aria-labelledby": "mls-recovery-missing-title",
            "aria-label": crate::i18n::tr("mls_recovery_missing.aria_label"),
            div {
                class: "modal event mls-recovery-modal mls-recovery-missing-banner",
                "data-testid": "mls-recovery-missing-banner",
                role: "dialog",
                "aria-modal": "true",
                div { class: "modal-head event-head",
                    h3 { id: "mls-recovery-missing-title", {crate::i18n::tr("mls_recovery_missing.title")} }
                    span { class: "muted", {crate::i18n::tr("mls_recovery_missing.subtitle")} }
                }
                div { class: "modal-body mls-recovery-modal-body",
                    div { class: "muted",
                        {crate::i18n::tr("mls_recovery_missing.description")}
                    }
                }
                div { class: "modal-foot mls-unlock-row",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "mls-recovery-missing-dismiss",
                        onclick: move |_| needs_mls_recovery_setup.set(false),
                        {crate::i18n::tr("mls_recovery_missing.button_dismiss")}
                    }
                }
            }
        }
    }
}
