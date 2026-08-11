//! Account creation entry point.
//!
//! Service-account policy, passwords, passkeys and email verification belong
//! to the Account Authority. Inkson starts the same canonical OIDC handoff and
//! performs principal custody only after the callback.

use dioxus::prelude::*;
use dioxus_router::Link;

use crate::ui::button::{Button, ButtonVariant};
use crate::ui::card::Card;
use crate::ui::input::Input;
use crate::ui::label::Label;

#[component]
pub fn RegistrationPanel(mut device_id: Signal<String>) -> Element {
    let mut principal_server = crate::app::SessionContext::get().base_url;
    let mut state_store = crate::app::SessionContext::get().state_store;
    let i18n = use_context::<crate::i18n::I18nSignal>();
    let mut busy = use_signal(|| false);
    let mut status = use_signal(|| {
        "Create or authenticate the service account at its Account Authority. Identity custody continues here after the callback."
            .to_owned()
    });

    rsx! {
        Card {
            class: "auth-panel",
            "data-testid": "registration-panel",
            role: "region",
            "aria-label": "Create account",
            div { class: "auth-brand",
                div { class: "auth-logo", "C" }
                div {
                    h1 { "Create account" }
                    p { "Arkret" }
                }
            }
            div { class: "auth-form",
                div { class: "auth-status", role: "status", "aria-live": "polite", "{status}" }
                Label { html_for: "register-server", "Principal server" }
                Input {
                    id: "register-server",
                    "data-testid": "register-server",
                    value: "{principal_server}",
                    disabled: busy(),
                    oninput: move |event: FormEvent| principal_server.set(event.value()),
                }
                div { class: "muted",
                    strong { "Account recovery" }
                    " restores the Account Authority login (password, passkey or OIDC). It does not recover or rotate your principal DID."
                }
                div { class: "muted",
                    strong { "Principal recovery" }
                    " uses the Recovery Key generated on this device. It does not reset the service-account password."
                }
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "register-open-account-authority",
                    disabled: busy(),
                    onclick: move |_| {
                        let server = principal_server();
                        let ui_locale = i18n.read().0.code().to_owned();
                        // This route is the explicit new-identity intent.  A
                        // device identity belongs to one principal, so it must
                        // never inherit the active/previous account's id.
                        let device = crate::config::new_device_id();
                        device_id.set(device.clone());
                        busy.set(true);
                        status.set("Opening the Account Authority…".to_owned());
                        spawn(async move {
                            let result = async {
                                #[cfg(target_arch = "wasm32")]
                                crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
                                    .await
                                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                                let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                                crate::secure_key_store::reset_device_seed_scope_for_signin(
                                    secure_store.as_ref(),
                                )?;
                                state_store.write().set_dpop_device_key(None);
                                state_store.write().begin_pending_login(device.trim(), None);
                                crate::secure_key_store::store_device_id_scoped(
                                    secure_store.as_ref(),
                                    None,
                                    device.trim(),
                                )?;
                                crate::views::login::start_oidc_strand(
                                    &server,
                                    device.trim(),
                                    "",
                                    crate::identity::account_auth::OidcAccountIntent::CreateIdentity,
                                    &ui_locale,
                                )
                                .await
                                .map_err(anyhow::Error::msg)
                            }
                            .await;
                            if let Err(error) = result {
                                status.set(format!("Could not open account creation: {error}"));
                                busy.set(false);
                            }
                        });
                    },
                    "Continue at Account Authority"
                }
                div { class: "auth-footer",
                    Link { to: crate::routes::Route::Login, "Already have an account? Sign in" }
                }
            }
        }
    }
}
