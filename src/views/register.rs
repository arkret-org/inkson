use dioxus::prelude::*;
use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    coauth::CoauthApi, config::LocalConfigStore, local_state::LocalStateStore,
    move_builder::encode_ed25519_did_key_multibase, views::helpers::persist_config,
};

#[derive(Clone, Debug)]
struct WebvhKeyMaterial {
    public_key_multibase: String,
    seed_hex: String,
    fingerprint: String,
}

#[derive(Clone, Debug)]
struct RegisteredWebvh {
    did: String,
    key_id: String,
    key_log_head: String,
    provider_id: String,
    document_url: String,
    log_url: String,
    public_key_multibase: String,
    public_fingerprint: String,
}

#[component]
pub fn RegisterPanel(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    initial_recovery: bool,
    on_register: EventHandler<()>,
) -> Element {
    let mut register_mode = use_signal(move || {
        if initial_recovery {
            "recovery".to_owned()
        } else {
            "new_webvh".to_owned()
        }
    });
    let mut new_step = use_signal(|| "username".to_owned());
    let mut username = use_signal(String::new);
    let mut email = use_signal(String::new);
    let mut verification_code = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut password_confirm = use_signal(String::new);
    let mut registration_id = use_signal(String::new);
    let mut skip_email_delivery = use_signal(|| false);
    let mut existing_did = use_signal(move || account_did());
    let mut existing_username = use_signal(String::new);
    let mut existing_proof_url = use_signal(String::new);
    let mut recovery_email = use_signal(String::new);
    let mut register_status = use_signal(String::new);
    let mut is_busy = use_signal(|| false);
    let mut registration_result = use_signal(|| Option::<RegisteredWebvh>::None);

    let mode = register_mode();
    let new_mode_class = if mode == "new_webvh" {
        "secondary auth-mode-button active"
    } else {
        "secondary auth-mode-button"
    };
    let existing_mode_class = if mode == "existing_did" {
        "secondary auth-mode-button active"
    } else {
        "secondary auth-mode-button"
    };
    let recovery_mode_class = if mode == "recovery" {
        "secondary auth-mode-button active"
    } else {
        "secondary auth-mode-button"
    };

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

                div { class: "auth-mode-grid",
                    button {
                        class: new_mode_class,
                        "data-testid": "register-path-new-webvh",
                        disabled: is_busy(),
                        onclick: move |_| {
                            register_mode.set("new_webvh".to_owned());
                            register_status.set(String::new());
                        },
                        "New did:webvh"
                    }
                    button {
                        class: existing_mode_class,
                        "data-testid": "register-path-existing-did",
                        disabled: is_busy(),
                        onclick: move |_| {
                            register_mode.set("existing_did".to_owned());
                            register_status.set(String::new());
                        },
                        "Existing DID"
                    }
                }

                button {
                    class: recovery_mode_class,
                    "data-testid": "register-recovery-link",
                    disabled: is_busy(),
                    onclick: move |_| {
                        register_mode.set("recovery".to_owned());
                        register_status.set(String::new());
                    },
                    "Lost password or account"
                }

                if mode == "new_webvh" {
                    if new_step() == "username" {
                        label { "Username" }
                        input {
                            "data-testid": "register-username-input",
                            "aria-label": "Username",
                            placeholder: "alice",
                            value: "{username}",
                            disabled: is_busy(),
                            oninput: move |event| username.set(event.value()),
                        }
                        button {
                            class: "primary auth-primary",
                            "data-testid": "next-to-email",
                            disabled: is_busy() || username().trim().is_empty(),
                            onclick: move |_| {
                                let principal = base_url();
                                let name = username();
                                is_busy.set(true);
                                register_status.set("Starting did:webvh registration...".to_owned());
                                spawn(async move {
                                    let result = async {
                                        let coauth = CoauthApi::new(&principal)?;
                                        let response = coauth
                                            .start_webvh_registration(name.trim(), principal.trim())
                                            .await?;
                                        if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                            anyhow::bail!(error);
                                        }
                                        let id = response.registration_id.clone().ok_or_else(|| {
                                            anyhow::anyhow!("coauth did not return a registration id")
                                        })?;
                                        Ok::<_, anyhow::Error>((id, response))
                                    }
                                    .await;
                                    match result {
                                        Ok((id, response)) => {
                                            registration_id.set(id);
                                            new_step.set("email".to_owned());
                                            register_status.set(format!(
                                                "Registration started with {}.",
                                                response.provider_id.as_deref().unwrap_or("soland.embedded")
                                            ));
                                        }
                                        Err(error) => register_status.set(format!("Registration failed: {error}")),
                                    }
                                    is_busy.set(false);
                                });
                            },
                            if is_busy() { "Working..." } else { "Continue" }
                        }
                    } else if new_step() == "email" {
                        label { "Email" }
                        input {
                            "data-testid": "register-email-input",
                            "aria-label": "Email",
                            placeholder: "alice@example.com",
                            value: "{email}",
                            disabled: is_busy(),
                            oninput: move |event| email.set(event.value()),
                        }
                        label { class: "auth-checkline",
                            input {
                                r#type: "checkbox",
                                "data-testid": "skip-email-delivery-toggle",
                                checked: skip_email_delivery(),
                                onchange: move |event| skip_email_delivery.set(event.value() == "true"),
                            }
                            "Skip email send in test"
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                disabled: is_busy(),
                                onclick: move |_| new_step.set("username".to_owned()),
                                "Back"
                            }
                            button {
                                class: "primary",
                                "data-testid": "send-verification-code-button",
                                disabled: is_busy() || email().trim().is_empty() || registration_id().trim().is_empty(),
                                onclick: move |_| {
                                    let principal = base_url();
                                    let id = registration_id();
                                    let mail = email();
                                    let skip = skip_email_delivery();
                                    is_busy.set(true);
                                    register_status.set("Sending verification code...".to_owned());
                                    spawn(async move {
                                        let result = async {
                                            let coauth = CoauthApi::new(&principal)?;
                                            let response = coauth
                                                .send_webvh_registration_email(id.trim(), mail.trim(), skip)
                                                .await?;
                                            if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                                anyhow::bail!(error);
                                            }
                                            Ok::<_, anyhow::Error>(response)
                                        }
                                        .await;
                                        match result {
                                            Ok(response) => {
                                                new_step.set("verify".to_owned());
                                                let mut message = if response.delivery.as_deref() == Some("skipped") {
                                                    "Verification code ready; email delivery skipped by test settings.".to_owned()
                                                } else {
                                                    "Verification code sent.".to_owned()
                                                };
                                                if let Some(code) = response.dev_code.as_deref() {
                                                    message.push_str(&format!(" Test code: {code}"));
                                                }
                                                register_status.set(message);
                                            }
                                            Err(error) => register_status.set(format!("Verification email failed: {error}")),
                                        }
                                        is_busy.set(false);
                                    });
                                },
                                "Send code"
                            }
                        }
                    } else if new_step() == "verify" {
                        label { "Verification code" }
                        input {
                            "data-testid": "register-verification-code",
                            "aria-label": "Verification code",
                            placeholder: "123456",
                            value: "{verification_code}",
                            disabled: is_busy(),
                            oninput: move |event| verification_code.set(event.value()),
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                disabled: is_busy(),
                                onclick: move |_| new_step.set("email".to_owned()),
                                "Back"
                            }
                            button {
                                class: "primary",
                                "data-testid": "verify-email-button",
                                disabled: is_busy() || verification_code().trim().is_empty(),
                                onclick: move |_| {
                                    let principal = base_url();
                                    let id = registration_id();
                                    let code = verification_code();
                                    is_busy.set(true);
                                    register_status.set("Verifying email...".to_owned());
                                    spawn(async move {
                                        let result = async {
                                            let coauth = CoauthApi::new(&principal)?;
                                            let response = coauth
                                                .verify_webvh_registration_email(id.trim(), code.trim())
                                                .await?;
                                            if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                                anyhow::bail!(error);
                                            }
                                            Ok::<_, anyhow::Error>(response)
                                        }
                                        .await;
                                        match result {
                                            Ok(_) => {
                                                new_step.set("password".to_owned());
                                                register_status.set("Email verified.".to_owned());
                                            }
                                            Err(error) => register_status.set(format!("Email verification failed: {error}")),
                                        }
                                        is_busy.set(false);
                                    });
                                },
                                "Verify"
                            }
                        }
                    } else if new_step() == "password" {
                        label { "Password" }
                        input {
                            r#type: "password",
                            "data-testid": "register-password-input",
                            "aria-label": "Password",
                            value: "{password}",
                            disabled: is_busy(),
                            oninput: move |event| password.set(event.value()),
                        }
                        label { "Confirm password" }
                        input {
                            r#type: "password",
                            "data-testid": "register-password-confirm",
                            "aria-label": "Confirm password",
                            value: "{password_confirm}",
                            disabled: is_busy(),
                            oninput: move |event| password_confirm.set(event.value()),
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                disabled: is_busy(),
                                onclick: move |_| new_step.set("verify".to_owned()),
                                "Back"
                            }
                            button {
                                class: "primary",
                                "data-testid": "complete-webvh-registration-button",
                                disabled: is_busy() || password().is_empty() || password_confirm().is_empty(),
                                onclick: move |_| {
                                    let principal = base_url();
                                    let id = registration_id();
                                    let device = device_id();
                                    let password_value = password();
                                    let password_confirm_value = password_confirm();
                                    if password_value != password_confirm_value {
                                        register_status.set("Passwords do not match.".to_owned());
                                        return;
                                    }
                                    if password_value.len() < 8 {
                                        register_status.set("Password must be at least 8 characters.".to_owned());
                                        return;
                                    }
                                    is_busy.set(true);
                                    register_status.set("Creating did:webvh...".to_owned());
                                    spawn(async move {
                                        let result = async {
                                            let key = generate_webvh_key_material()?;
                                            let coauth = CoauthApi::new(&principal)?;
                                            let response = coauth
                                                .finish_webvh_registration(
                                                    id.trim(),
                                                    key.public_key_multibase.as_str(),
                                                    "key-1",
                                                    device.trim(),
                                                    password_value.as_str(),
                                                    password_confirm_value.as_str(),
                                                )
                                                .await?;
                                            if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                                anyhow::bail!(error);
                                            }
                                            Ok::<_, anyhow::Error>((response, key))
                                        }
                                        .await;
                                        match result {
                                            Ok((response, key)) => {
                                                let did = response.did.clone();
                                                let public_key_multibase = key.public_key_multibase.clone();
                                                let seed_hex = key.seed_hex.clone();
                                                let public_fingerprint = key.fingerprint.clone();
                                                let key_id = response.key_id.clone().unwrap_or_else(|| format!("{did}#key-1"));
                                                let provider_id = response.provider_id.clone().unwrap_or_else(|| "soland.embedded".to_owned());
                                                let key_log_head = response.key_log_head.clone().unwrap_or_else(|| "missing".to_owned());
                                                let document_url = response.document_url.clone().unwrap_or_default();
                                                let log_url = response.log_url.clone().unwrap_or_default();
                                                let key_record = json!({
                                                    "kind": "cx.webvh.update_key.v1",
                                                    "did": did,
                                                    "key_id": key_id,
                                                    "provider_id": provider_id,
                                                    "public_key_multibase": public_key_multibase,
                                                    "seed_hex": seed_hex,
                                                    "public_fingerprint": public_fingerprint,
                                                    "created_at": chrono::Utc::now().to_rfc3339(),
                                                })
                                                .to_string();
                                                state_store.write().save_private_data(
                                                    did.as_str(),
                                                    "webvh.update_key.v1",
                                                    key_record,
                                                );
                                                account_did.set(did.clone());
                                                persist_config(
                                                    config_store,
                                                    principal,
                                                    did.clone(),
                                                    device,
                                                    String::new(),
                                                );
                                                registration_result.set(Some(RegisteredWebvh {
                                                    did,
                                                    key_id,
                                                    key_log_head,
                                                    provider_id,
                                                    document_url,
                                                    log_url,
                                                    public_key_multibase,
                                                    public_fingerprint,
                                                }));
                                                new_step.set("complete".to_owned());
                                                register_status.set("Account registered successfully.".to_owned());
                                            }
                                            Err(error) => register_status.set(format!("Registration failed: {error}")),
                                        }
                                        is_busy.set(false);
                                    });
                                },
                                "Create DID"
                            }
                        }
                    } else if let Some(summary) = registration_result() {
                        div { class: "auth-result", "data-testid": "registration-complete",
                            strong { "Account registered successfully" }
                            div { "DID: " span { "data-testid": "registered-did-webvh", "{summary.did}" } }
                            div { "Provider: {summary.provider_id}" }
                            div { "Key: " span { "data-testid": "register-key-id", "{summary.key_id}" } }
                            div { "Key log head: " span { "data-testid": "register-key-log-head", "{summary.key_log_head}" } }
                            div { "Public update key: {summary.public_fingerprint}" }
                            if !summary.document_url.is_empty() {
                                div { "Document: {summary.document_url}" }
                            }
                            if !summary.log_url.is_empty() {
                                div { "Log: {summary.log_url}" }
                            }
                            div { "Public key material: {summary.public_key_multibase}" }
                        }
                        button {
                            class: "primary auth-primary",
                            "data-testid": "back-to-login-after-registration",
                            onclick: move |_| on_register.call(()),
                            "Back to sign in"
                        }
                    }
                } else if mode == "existing_did" {
                    label { "DID" }
                    input {
                        "data-testid": "existing-did-input",
                        "aria-label": "Existing DID",
                        placeholder: "did:web:team.example",
                        value: "{existing_did}",
                        disabled: is_busy(),
                        oninput: move |event| {
                            let value = event.value();
                            existing_did.set(value.clone());
                            account_did.set(value);
                        },
                    }
                    label { "Username" }
                    input {
                        "data-testid": "existing-did-username-input",
                        "aria-label": "Username for existing DID",
                        placeholder: "team",
                        value: "{existing_username}",
                        disabled: is_busy(),
                        oninput: move |event| existing_username.set(event.value()),
                    }
                    button {
                        class: "primary auth-primary",
                        "data-testid": "start-existing-did-registration-button",
                        disabled: is_busy() || existing_did().trim().is_empty(),
                        onclick: move |_| {
                            let principal = base_url();
                            let did = existing_did();
                            let name = existing_username();
                            let device = device_id();
                            is_busy.set(true);
                            register_status.set("Starting DID binding...".to_owned());
                            spawn(async move {
                                let result = async {
                                    let coauth = CoauthApi::new(&principal)?;
                                    let response = coauth
                                        .bind_existing_did_registration(did.trim(), name.trim(), device.trim())
                                        .await?;
                                    if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                        anyhow::bail!(error);
                                    }
                                    Ok::<_, anyhow::Error>(response)
                                }
                                .await;
                                match result {
                                    Ok(response) => {
                                        if let Some(url) = response.proof_url.as_deref() {
                                            existing_proof_url.set(url.to_owned());
                                        }
                                        let registered_did = response.did.clone().unwrap_or(did);
                                        account_did.set(registered_did.clone());
                                        persist_config(
                                            config_store,
                                            principal,
                                            registered_did.clone(),
                                            device,
                                            String::new(),
                                        );
                                        register_status.set(format!(
                                            "Existing DID registration {}.",
                                            response.next_step.as_deref().unwrap_or(response.status.as_str())
                                        ));
                                    }
                                    Err(error) => register_status.set(format!("DID binding failed: {error}")),
                                }
                                is_busy.set(false);
                            });
                        },
                        if is_busy() { "Working..." } else { "Continue" }
                    }
                    if !existing_proof_url().is_empty() {
                        div { class: "auth-result", "data-testid": "existing-did-proof",
                            strong { "Proof" }
                            div { "{existing_proof_url}" }
                        }
                    }
                } else {
                    label { "Email" }
                    input {
                        "data-testid": "recovery-email-input",
                        "aria-label": "Recovery email",
                        placeholder: "alice@example.com",
                        value: "{recovery_email}",
                        disabled: is_busy(),
                        oninput: move |event| recovery_email.set(event.value()),
                    }
                    button {
                        class: "primary auth-primary",
                        "data-testid": "start-recovery-button",
                        disabled: is_busy() || recovery_email().trim().is_empty(),
                        onclick: move |_| {
                            let principal = base_url();
                            let mail = recovery_email();
                            is_busy.set(true);
                            register_status.set("Starting recovery...".to_owned());
                            spawn(async move {
                                let result = async {
                                    let coauth = CoauthApi::new(&principal)?;
                                    let response = coauth.start_recovery(mail.trim()).await?;
                                    if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                        anyhow::bail!(error);
                                    }
                                    Ok::<_, anyhow::Error>(response)
                                }
                                .await;
                                match result {
                                    Ok(response) => {
                                        let id = response
                                            .flow_session_id
                                            .or(response.id)
                                            .unwrap_or_else(|| "accepted".to_owned());
                                        register_status.set(format!("Recovery request accepted: {id}"));
                                    }
                                    Err(error) => register_status.set(format!("Recovery failed: {error}")),
                                }
                                is_busy.set(false);
                            });
                        },
                        if is_busy() { "Working..." } else { "Send recovery email" }
                    }
                }

                button {
                    class: "secondary auth-secondary",
                    "data-testid": "back-to-login-link",
                    disabled: is_busy(),
                    onclick: move |_| on_register.call(()),
                    "Back to sign in"
                }

                if !register_status().is_empty() {
                    div {
                        class: "auth-status",
                        "data-testid": if mode == "recovery" { "recovery-status" } else { "register-status" },
                        role: "status",
                        "{register_status}"
                    }
                }
            }
        }
    }
}

fn api_response_error(status: &str, error: Option<&str>) -> Option<String> {
    match status {
        "ok" | "success" | "sent" | "accepted" | "pending" | "proof_required" => None,
        other => Some(error.unwrap_or(other).to_owned()),
    }
}

fn generate_webvh_key_material() -> anyhow::Result<WebvhKeyMaterial> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|error| anyhow::anyhow!("rng fill: {error}"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key_multibase = encode_ed25519_did_key_multibase(&signing_key.verifying_key());
    let digest = Sha256::digest(public_key_multibase.as_bytes());
    Ok(WebvhKeyMaterial {
        public_key_multibase,
        seed_hex: hex_encode(&seed),
        fingerprint: format!("sha256:{}", hex_encode(&digest[..8])),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
