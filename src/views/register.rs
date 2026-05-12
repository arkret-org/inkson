use dioxus::prelude::*;

use crate::{
    config::LocalConfigStore,
    views::{helpers::persist_config, login::start_oidc_flow},
};

#[component]
pub fn RegisterPanel(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    on_register: EventHandler<()>,
) -> Element {
    let mut login_hint = use_signal(move || account_did());
    let mut register_status = use_signal(String::new);
    let mut is_busy = use_signal(|| false);

    rsx! {
        section { class: "auth-panel", "data-testid": "register-panel", role: "region", "aria-label": "Register",
            div { class: "auth-brand",
                div { class: "auth-logo", "C" }
                div {
                    h1 { "Create account" }
                    p { "Contrix" }
                }
            }

            div { class: "auth-form",
                label { "Principal server" }
                input {
                    "data-testid": "register-server-url",
                    "aria-label": "Principal server URL",
                    value: "{base_url}",
                    disabled: is_busy(),
                    oninput: move |event| {
                        let value = event.value();
                        base_url.set(value.clone());
                        persist_config(config_store, value, account_did(), device_id(), String::new());
                    },
                }

                label { "Account" }
                input {
                    "data-testid": "register-account-hint",
                    "aria-label": "Account",
                    placeholder: "Email or DID",
                    value: "{login_hint}",
                    disabled: is_busy(),
                    oninput: move |event| {
                        let value = event.value();
                        login_hint.set(value.clone());
                        account_did.set(value);
                    },
                }

                button {
                    class: "primary auth-primary",
                    "data-testid": "start-server-registration-button",
                    disabled: is_busy(),
                    onclick: move |_| {
                        let principal = base_url();
                        let actor = login_hint();
                        let device = device_id();
                        is_busy.set(true);
                        register_status.set("Opening server registration...".to_owned());
                        spawn(async move {
                            match start_oidc_flow(&principal, actor.trim(), device.trim(), true).await {
                                Ok(()) => {
                                    persist_config(
                                        config_store,
                                        principal,
                                        actor,
                                        device,
                                        String::new(),
                                    );
                                }
                                Err(error) => {
                                    is_busy.set(false);
                                    register_status.set(error);
                                }
                            }
                        });
                    },
                    if is_busy() { "Working..." } else { "Continue" }
                }

                button {
                    class: "secondary auth-secondary",
                    "data-testid": "back-to-login-link",
                    onclick: move |_| on_register.call(()),
                    "Back to sign in"
                }

                if !register_status().is_empty() {
                    div { class: "auth-status", "data-testid": "register-status", role: "status", "{register_status}" }
                }
            }
        }
    }
}
