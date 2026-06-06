use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::recovery_crypto::normalize_recovery_key_input;
use crate::views::helpers::{ApiCallError, with_authed_api};

/// Account-MLS-secret auto-unlock prompt (step 3 of the recovery flow).
///
/// Mounted once near the app shell and rendered ONLY when `needs_mls_unlock`
/// is `true` — which the boot-time detection in `App` sets when this device
/// is missing usable local MLS history and the server holds an
/// `mls_account_secret` backup. The user supplies their recovery key
/// and we call
/// [`crate::mls::account_recovery::auto_restore_mls_history_with_passphrase`]
/// to import the account secret and restore every `mls_history` backup. The
/// method name reflects the wire `passphrase_kdf` recipient method; the UI
/// presents it as a generated recovery key.
#[component]
pub fn MlsUnlockPrompt(
    base_url: Signal<String>,
    token: Signal<String>,
    actor_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
    needs_mls_unlock: Signal<bool>,
    restore_payload_cache: Signal<Option<serde_json::Value>>,
) -> Element {
    let mut passphrase = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut busy = use_signal(|| false);

    if !needs_mls_unlock() {
        return rsx! {};
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
        let actor = actor_did();
        let device = device_id();
        let mut state_store = state_store;
        let mut needs_mls_unlock = needs_mls_unlock;
        let mut restore_payload_cache = restore_payload_cache;
        busy.set(true);
        status.set(crate::i18n::tr("mls_unlock.status.fetching"));
        spawn(async move {
            let fetch_actor = actor.clone();
            let fetch_device = device.clone();
            let payload_result = with_authed_api(&base, session, |api| async move {
                crate::mls::account_recovery::fetch_mls_restore_payload_with_unlock_proof(
                    &api,
                    &fetch_actor,
                    &fetch_device,
                )
                .await
            })
            .await;
            let result = match payload_result {
                Ok(payload) => {
                    restore_payload_cache.set(Some(payload.clone()));
                    let history_count =
                        crate::mls::account_recovery::select_mls_history_backups(&payload).len();
                    status.set(format!(
                        "{} {} {}",
                        crate::i18n::tr("mls_unlock.status.restoring_prefix"),
                        history_count,
                        crate::i18n::tr("mls_unlock.status.restoring_suffix")
                    ));
                    crate::api::sleep_for(std::time::Duration::from_millis(16)).await;
                    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
                    let mut store = state_store.write();
                    crate::mls::account_recovery::restore_mls_history_with_passphrase_from_payload(
                        &payload,
                        &mut store,
                        secure_store.as_ref(),
                        &actor,
                        &device,
                        pass.as_bytes(),
                    )
                    .map_err(ApiCallError::Failed)
                }
                Err(err) => Err(err),
            };
            busy.set(false);
            match result {
                Ok(report) => {
                    if let Some(err) = report.first_error {
                        // Some backups failed even though the call returned Ok —
                        // keep the prompt open so the user can retry.
                        status.set(format!(
                            "{} {} {}; {} {}: {err}",
                            crate::i18n::tr("mls_unlock.status.restored_prefix"),
                            report.restored,
                            crate::i18n::tr("mls_unlock.status.restored_suffix"),
                            report.failed,
                            crate::i18n::tr("mls_unlock.status.failed_suffix")
                        ));
                    } else {
                        let restored_status = format!(
                            "{} {} {}",
                            crate::i18n::tr("mls_unlock.status.restored_prefix"),
                            report.restored,
                            crate::i18n::tr("mls_unlock.status.restored_suffix")
                        );
                        passphrase.set(String::new());
                        restore_payload_cache.set(None);
                        status.set(restored_status);
                        crate::api::sleep_for(std::time::Duration::from_millis(750)).await;
                        needs_mls_unlock.set(false);
                    }
                }
                Err(err) => {
                    // Wrong passphrase / network: keep prompt open, surface reason.
                    status.set(err.display());
                }
            }
        });
    };

    rsx! {
        div {
            class: "modal-overlay mls-recovery-modal-overlay",
            "data-testid": "mls-unlock-modal",
            div {
                class: "modal event mls-recovery-modal mls-unlock-banner",
                "data-testid": "mls-unlock-banner",
                role: "dialog",
                "aria-modal": "true",
                "aria-labelledby": "mls-unlock-title",
                "aria-label": crate::i18n::tr("mls_unlock.aria_label"),
                div { class: "modal-head event-head",
                    h3 { id: "mls-unlock-title", {crate::i18n::tr("mls_unlock.title")} }
                    span { class: "muted", {crate::i18n::tr("mls_unlock.subtitle")} }
                }
                div { class: "modal-body mls-recovery-modal-body",
                    div { class: "muted",
                        {crate::i18n::tr("mls_unlock.description")}
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
                    input {
                        r#type: "password",
                        "data-testid": "mls-unlock-passphrase",
                        placeholder: crate::i18n::tr("mls_unlock.placeholder"),
                        value: "{passphrase}",
                        disabled: busy(),
                        oninput: move |evt| passphrase.set(evt.value()),
                    }
                    button {
                        class: "primary",
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

/// Fresh-device recovery diagnostic shown when encrypted Realm/history exists
/// but this account has no recovery-key-backed `mls_account_secret` backup on
/// the server. In that state `MlsUnlockPrompt` cannot ask for a recovery key
/// because there is no account-secret backup to open, so the app must tell the
/// user to create the recovery backup from an existing unlocked device instead
/// of silently rendering empty encrypted surfaces.
#[component]
pub fn MlsRecoverySetupMissingBanner(
    mut needs_mls_recovery_setup: Signal<bool>,
    actor_did: Signal<String>,
) -> Element {
    if !needs_mls_recovery_setup() {
        return rsx! {};
    }

    let actor = actor_did();
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
        div {
            class: "modal-overlay mls-recovery-modal-overlay",
            "data-testid": "mls-recovery-missing-modal",
            div {
                class: "modal event mls-recovery-modal mls-recovery-missing-banner",
                "data-testid": "mls-recovery-missing-banner",
                role: "dialog",
                "aria-modal": "true",
                "aria-labelledby": "mls-recovery-missing-title",
                "aria-label": crate::i18n::tr("mls_recovery_missing.aria_label"),
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
                    button {
                        class: "secondary",
                        "data-testid": "mls-recovery-missing-dismiss",
                        onclick: move |_| needs_mls_recovery_setup.set(false),
                        {crate::i18n::tr("mls_recovery_missing.button_dismiss")}
                    }
                }
            }
        }
    }
}
