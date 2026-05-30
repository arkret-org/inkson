use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::views::helpers::{ApiCallError, with_authed_api};

/// Account-MLS-secret auto-unlock prompt (step 3 of the recovery flow).
///
/// Mounted once near the app shell and rendered ONLY when `needs_mls_unlock`
/// is `true` — which the boot-time detection in `App` sets when this device
/// has no local account MLS secret yet but the server holds an
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
            status.set("Enter your recovery passphrase to unlock encrypted history.".to_owned());
            return;
        }
        let base = base_url();
        let session = token();
        let actor = actor_did();
        let device = device_id();
        let mut state_store = state_store;
        let mut needs_mls_unlock = needs_mls_unlock;
        busy.set(true);
        status.set("Unlocking encrypted history…".to_owned());
        spawn(async move {
            let result = match with_authed_api(&base, session, |api| async move {
                crate::mls::account_recovery::fetch_mls_restore_payload(&api).await
            })
            .await
            {
                Ok(payload) => {
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
                            "Restored {} space(s); {} failed: {err}",
                            report.restored, report.failed
                        ));
                    } else {
                        passphrase.set(String::new());
                        needs_mls_unlock.set(false);
                        status.set(format!("Restored {} space(s).", report.restored));
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
            "aria-label": "Unlock encrypted history",
            div { class: "event-head",
                strong { "Unlock encrypted history" }
                span { class: "muted", "account MLS secret" }
            }
            div { class: "muted",
                "This device doesn't have your account MLS history secret yet. Enter your recovery passphrase to restore encrypted spaces from your account backup."
            }
            div { class: "mls-unlock-row",
                input {
                    r#type: "password",
                    "data-testid": "mls-unlock-passphrase",
                    placeholder: "Recovery passphrase",
                    value: "{passphrase}",
                    disabled: busy(),
                    oninput: move |evt| passphrase.set(evt.value()),
                }
                button {
                    class: "primary",
                    "data-testid": "mls-unlock-submit",
                    disabled: busy(),
                    onclick: on_unlock,
                    if busy() { "Unlocking…" } else { "Unlock history" }
                }
            }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "mls-unlock-status", "{status}" }
            }
        }
    }
}
