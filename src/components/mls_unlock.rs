use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::views::helpers::{ApiCallError, with_authed_api};

/// Account-MLS-secret auto-unlock prompt (step 3 of the recovery flow).
///
/// Mounted once near the app shell and rendered ONLY when `needs_mls_unlock`
/// is `true` — which the boot-time detection in `App` sets when this device
/// is missing usable local MLS history and the server holds an
/// `mls_account_secret` backup. The user supplies their recovery passphrase
/// and we call
/// [`crate::mls::account_recovery::auto_restore_mls_history_with_passphrase`]
/// to import the account secret and restore every `mls_history` backup.
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
        let pass = passphrase();
        if pass.is_empty() {
            status.set(crate::i18n::tr("mls_unlock.status.enter_passphrase"));
            return;
        }
        let base = base_url();
        let session = token();
        let actor = actor_did();
        let device = device_id();
        let mut state_store = state_store;
        let mut needs_mls_unlock = needs_mls_unlock;
        let mut restore_payload_cache = restore_payload_cache;
        let cached_payload = restore_payload_cache();
        busy.set(true);
        status.set(crate::i18n::tr("mls_unlock.status.fetching"));
        spawn(async move {
            let payload_result = if let Some(payload) = cached_payload {
                Ok(payload)
            } else {
                with_authed_api(&base, session, |api| async move {
                    crate::mls::account_recovery::fetch_mls_restore_payload(&api).await
                })
                .await
            };
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
            class: "event mls-unlock-banner",
            "data-testid": "mls-unlock-banner",
            role: "region",
            "aria-label": crate::i18n::tr("mls_unlock.aria_label"),
            div { class: "event-head",
                strong { {crate::i18n::tr("mls_unlock.title")} }
                span { class: "muted", {crate::i18n::tr("mls_unlock.subtitle")} }
            }
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
            div { class: "mls-unlock-row",
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
            if !status().is_empty() {
                div { class: "muted", "data-testid": "mls-unlock-status", "{status}" }
            }
        }
    }
}
