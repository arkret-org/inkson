use dioxus::prelude::*;
use dioxus_router::Link;

use crate::identity::principal_registration::{
    RegistrationStart, finish_registration, prepare_registration_checkpoint,
    registration_start_from_checkpoint, send_registration_email, start_registration,
    validate_checkpoint_recovery_key, verify_registration_email,
};
use crate::state::{PendingPrincipalRegistration, PendingPrincipalRegistrationStage};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::card::Card;
use crate::ui::input::Input;
use crate::ui::label::Label;

#[component]
pub fn RegistrationPanel(mut device_id: Signal<String>) -> Element {
    let mut base_url = crate::app::SessionContext::get().base_url;
    let mut state_store = crate::app::SessionContext::get().state_store;
    let i18n = use_context::<crate::i18n::I18nSignal>();
    let initial_checkpoint = state_store.read().pending_principal_registration();
    let mut checkpoint = use_signal(|| initial_checkpoint.clone());
    let mut start = use_signal(|| {
        initial_checkpoint
            .as_ref()
            .map(registration_start_from_checkpoint)
    });
    let mut handle = use_signal(|| {
        initial_checkpoint
            .as_ref()
            .map(|value| value.handle.clone())
            .unwrap_or_default()
    });
    let mut email = use_signal(|| {
        initial_checkpoint
            .as_ref()
            .map(|value| value.email.clone())
            .unwrap_or_default()
    });
    let mut password = use_signal(String::new);
    let mut password_confirm = use_signal(String::new);
    let mut email_code = use_signal(String::new);
    let mut live_recovery_key = use_signal(String::new);
    let mut recovery_entry = use_signal(String::new);
    let mut dev_code = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut status = use_signal(|| {
        if initial_checkpoint.is_some() {
            "A public identity draft is saved. Continue the same registration; do not create a second identity."
                .to_owned()
        } else {
            "Your Recovery Key and identity root are generated only on this device.".to_owned()
        }
    });

    let mut continue_sign_in = move |registration: PendingPrincipalRegistration| {
        let principal_server = registration.principal_server_url.clone();
        let actor = registration.did.clone();
        let device = registration.device_id.clone();
        let ui_locale = i18n.read().0.code().to_owned();
        device_id.set(device.clone());
        spawn(async move {
            let outcome = async {
                #[cfg(target_arch = "wasm32")]
                crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
                    .await
                    .map_err(|error| format!("secure key store is not ready: {error}"))?;
                let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                crate::secure_key_store::reset_device_seed_scope_for_signin(secure_store.as_ref())
                    .map_err(|error| format!("reset sign-in key scope: {error}"))?;
                state_store.write().set_dpop_device_key(None);
                state_store.write().begin_pending_login(device.trim(), None);
                crate::secure_key_store::store_device_id_scoped(
                    secure_store.as_ref(),
                    None,
                    device.trim(),
                )
                .map_err(|error| format!("store bootstrap device id: {error}"))?;
                crate::views::login::start_oidc_strand(
                    &principal_server,
                    device.trim(),
                    "",
                    actor.as_str(),
                    &ui_locale,
                )
                .await
            }
            .await;
            if let Err(error) = outcome {
                status.set(format!("Could not start sign-in: {error}"));
            }
        });
    };

    rsx! {
        Card {
            class: "auth-panel",
            "data-testid": "registration-panel",
            role: "region",
            "aria-label": "Create identity",
            div { class: "auth-brand",
                div { class: "auth-logo", "C" }
                div {
                    h1 { "Create identity" }
                    p { "Arkret" }
                }
            }
            div { class: "auth-form",
                div { class: "auth-status", role: "status", "aria-live": "polite", "{status}" }

                if start().is_none() {
                    Label { html_for: "register-server", "Principal server" }
                    Input {
                        id: "register-server",
                        "data-testid": "register-server",
                        value: "{base_url}",
                        disabled: busy(),
                        oninput: move |event: FormEvent| base_url.set(event.value()),
                    }
                    Label { html_for: "register-handle", "Handle" }
                    Input {
                        id: "register-handle",
                        "data-testid": "register-handle",
                        autocomplete: "username",
                        value: "{handle}",
                        disabled: busy(),
                        oninput: move |event: FormEvent| handle.set(event.value()),
                    }
                    Label { html_for: "register-email", "Email" }
                    Input {
                        id: "register-email",
                        "data-testid": "register-email",
                        r#type: "email",
                        autocomplete: "email",
                        value: "{email}",
                        disabled: busy(),
                        oninput: move |event: FormEvent| email.set(event.value()),
                    }
                    Label { html_for: "register-password", "Password" }
                    Input {
                        id: "register-password",
                        "data-testid": "register-password",
                        r#type: "password",
                        autocomplete: "new-password",
                        value: "{password}",
                        disabled: busy(),
                        oninput: move |event: FormEvent| password.set(event.value()),
                    }
                    Label { html_for: "register-password-confirm", "Confirm password" }
                    Input {
                        id: "register-password-confirm",
                        "data-testid": "register-password-confirm",
                        r#type: "password",
                        autocomplete: "new-password",
                        value: "{password_confirm}",
                        disabled: busy(),
                        oninput: move |event: FormEvent| password_confirm.set(event.value()),
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "register-prepare",
                        disabled: busy(),
                        onclick: move |_| {
                            let server = base_url();
                            let requested_handle = handle().trim().to_owned();
                            let requested_email = email().trim().to_owned();
                            if requested_handle.is_empty() || requested_email.is_empty() {
                                status.set("Handle and email are required.".to_owned());
                                return;
                            }
                            if password().is_empty() || password() != password_confirm() {
                                status.set("Enter the same non-empty password twice.".to_owned());
                                return;
                            }
                            busy.set(true);
                            status.set("Starting registration and preparing cold custody…".to_owned());
                            spawn(async move {
                                let outcome = async {
                                    let started = start_registration(&server, &requested_handle).await?;
                                    let sent = send_registration_email(&started, &requested_email).await?;
                                    let recovery_key = crate::recovery_crypto::generate_recovery_key()?;
                                    Ok::<_, anyhow::Error>((started, sent, recovery_key))
                                }
                                .await;
                                match outcome {
                                    Ok((started, sent, recovery_key)) => {
                                        dev_code.set(sent.dev_code.unwrap_or_default());
                                        start.set(Some(started));
                                        live_recovery_key.set(recovery_key);
                                        recovery_entry.set(String::new());
                                        status.set("Write all 24 words down offline, then re-enter them exactly. Nothing has been published yet.".to_owned());
                                    }
                                    Err(error) => status.set(format!("Could not start registration: {error}")),
                                }
                                busy.set(false);
                            });
                        },
                        "Generate Recovery Key"
                    }
                } else {
                    if !live_recovery_key().is_empty() {
                        Label { html_for: "register-recovery-key", "Recovery Key — shown once" }
                        textarea {
                            id: "register-recovery-key",
                            class: "form-input",
                            "data-testid": "register-recovery-key",
                            readonly: true,
                            rows: "5",
                            value: "{live_recovery_key}",
                        }
                        Label { html_for: "register-recovery-confirm", "Re-enter all 24 words" }
                    } else if checkpoint().as_ref().is_some_and(|value| value.stage == PendingPrincipalRegistrationStage::CustodyConfirmed) {
                        Label { html_for: "register-recovery-confirm", "Recovery Key for the saved draft" }
                    }
                    if !live_recovery_key().is_empty()
                        || checkpoint().as_ref().is_some_and(|value| value.stage == PendingPrincipalRegistrationStage::CustodyConfirmed)
                    {
                        textarea {
                            id: "register-recovery-confirm",
                            class: "form-input",
                            "data-testid": "register-recovery-confirm",
                            rows: "5",
                            autocomplete: "off",
                            value: "{recovery_entry}",
                            disabled: busy(),
                            oninput: move |event| recovery_entry.set(event.value()),
                        }
                    }
                    if checkpoint().is_none() {
                        Label { html_for: "register-email-code", "Email verification code" }
                        Input {
                            id: "register-email-code",
                            "data-testid": "register-email-code",
                            autocomplete: "one-time-code",
                            value: "{email_code}",
                            disabled: busy(),
                            oninput: move |event: FormEvent| email_code.set(event.value()),
                        }
                        if !dev_code().is_empty() {
                            div {
                                class: "muted",
                                "data-testid": "register-dev-code",
                                "Local development code: {dev_code}"
                            }
                        }
                    }
                    if checkpoint().as_ref().is_some_and(|value| value.stage == PendingPrincipalRegistrationStage::CustodyConfirmed) {
                        Label { html_for: "register-resume-password", "Password" }
                        Input {
                            id: "register-resume-password",
                            r#type: "password",
                            autocomplete: "new-password",
                            value: "{password}",
                            disabled: busy(),
                            oninput: move |event: FormEvent| password.set(event.value()),
                        }
                        Label { html_for: "register-resume-password-confirm", "Confirm password" }
                        Input {
                            id: "register-resume-password-confirm",
                            r#type: "password",
                            autocomplete: "new-password",
                            value: "{password_confirm}",
                            disabled: busy(),
                            oninput: move |event: FormEvent| password_confirm.set(event.value()),
                        }
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "register-commit",
                        disabled: busy(),
                        onclick: move |_| {
                            let Some(started): Option<RegistrationStart> = start() else {
                                return;
                            };
                            if let Some(saved) = checkpoint()
                                && saved.stage == PendingPrincipalRegistrationStage::DidBound
                            {
                                status.set("Opening server sign-in for the bound identity…".to_owned());
                                continue_sign_in(saved);
                                return;
                            }
                            let supplied_recovery = if live_recovery_key().is_empty() {
                                recovery_entry()
                            } else {
                                if !crate::recovery_crypto::recovery_key_confirmation_matches(
                                    &live_recovery_key(),
                                    &recovery_entry(),
                                ) {
                                    status.set("The 24 words do not match. Nothing was published.".to_owned());
                                    return;
                                }
                                live_recovery_key()
                            };
                            if password().is_empty() || password() != password_confirm() {
                                status.set("Enter the same non-empty password twice.".to_owned());
                                return;
                            }
                            let verification_code = email_code();
                            let requested_handle = handle();
                            let requested_email = email();
                            let requested_device = if device_id().trim().is_empty() {
                                crate::config::new_device_id()
                            } else {
                                device_id()
                            };
                            device_id.set(requested_device.clone());
                            busy.set(true);
                            status.set("Confirming custody and publishing the signed DID inception…".to_owned());
                            spawn(async move {
                                let outcome = async {
                                    let mut saved = match checkpoint() {
                                        Some(saved) => {
                                            validate_checkpoint_recovery_key(&saved, &supplied_recovery)?;
                                            saved
                                        }
                                        None => {
                                            verify_registration_email(&started, &verification_code).await?;
                                            let saved = prepare_registration_checkpoint(
                                                &started,
                                                &requested_handle,
                                                &requested_email,
                                                &requested_device,
                                                &supplied_recovery,
                                            )?;
                                            let barrier = {
                                                let mut store = state_store.write();
                                                store.set_pending_principal_registration(Some(saved.clone()))?;
                                                store.begin_durable_flush()?
                                            };
                                            barrier.wait().await?;
                                            checkpoint.set(Some(saved.clone()));
                                            saved
                                        }
                                    };
                                    finish_registration(&saved, &password(), &password_confirm()).await?;
                                    saved.stage = PendingPrincipalRegistrationStage::DidBound;
                                    let barrier = {
                                        let mut store = state_store.write();
                                        store.set_pending_principal_registration(Some(saved.clone()))?;
                                        store.begin_durable_flush()?
                                    };
                                    barrier.wait().await?;
                                    Ok::<_, anyhow::Error>(saved)
                                }
                                .await;
                                match outcome {
                                    Ok(saved) => {
                                        checkpoint.set(Some(saved.clone()));
                                        live_recovery_key.set(String::new());
                                        recovery_entry.set(String::new());
                                        status.set("Identity entry 0 is accepted and bound. Opening server sign-in…".to_owned());
                                        continue_sign_in(saved);
                                    }
                                    Err(error) => status.set(format!("Registration did not complete: {error}")),
                                }
                                busy.set(false);
                            });
                        },
                        if checkpoint().as_ref().is_some_and(|value| value.stage == PendingPrincipalRegistrationStage::DidBound) {
                            "Continue sign-in"
                        } else {
                            "Confirm and create identity"
                        }
                    }
                }

                div { class: "auth-footer",
                    Link { to: crate::routes::Route::Login, "Already have an identity? Sign in" }
                }
            }
        }
    }
}
