use dioxus::prelude::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    coauth::{CoauthApi, resolve_principal_auth_server_url},
    config::{LocalConfigStore, validate_server_url},
    local_state::LocalStateStore,
    move_builder::encode_ed25519_did_key_multibase,
    views::helpers::persist_config,
};

#[derive(Clone, Debug)]
struct WebvhKeyMaterial {
    signing_key: SigningKey,
    public_key_multibase: String,
    seed_hex: String,
    fingerprint: String,
}

#[derive(Clone, Debug)]
struct RegisteredWebvh {
    did: String,
    did_key_id: String,
    update_key_id: String,
    key_log_head: String,
    provider_id: String,
    document_url: String,
    log_url: String,
    did_public_key_multibase: String,
    did_public_fingerprint: String,
    did_private_seed_hex: String,
    update_public_key_multibase: String,
    update_public_fingerprint: String,
    update_private_seed_hex: String,
    backup_filename: String,
    backup_json: String,
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
    let mut existing_did = use_signal(move || account_did());
    let mut existing_proof_url = use_signal(String::new);
    let mut recovery_email = use_signal(String::new);
    let mut register_status = use_signal(String::new);
    let mut is_busy = use_signal(|| false);
    let mut registration_result = use_signal(|| Option::<RegisteredWebvh>::None);
    let mut auth_server_url = use_signal(String::new);

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
                        auth_server_url.set(String::new());
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
                                let auth_hint = auth_server_url();
                                let name = username();
                                is_busy.set(true);
                                register_status.set("Starting did:webvh registration...".to_owned());
                                spawn(async move {
                                    let result = async {
                                        let (auth_base, coauth) =
                                            coauth_for_principal(principal.trim(), auth_hint.trim()).await?;
                                        let response = coauth
                                            .start_webvh_registration(name.trim(), principal.trim())
                                            .await?;
                                        if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                            anyhow::bail!(error);
                                        }
                                        let id = response.registration_id.clone().ok_or_else(|| {
                                            anyhow::anyhow!("coauth did not return a registration id")
                                        })?;
                                        Ok::<_, anyhow::Error>((auth_base, id, response))
                                    }
                                    .await;
                                    match result {
                                        Ok((auth_base, id, response)) => {
                                            auth_server_url.set(auth_base);
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
                                let auth_hint = auth_server_url();
                                let id = registration_id();
                                let mail = email();
                                is_busy.set(true);
                                register_status.set("Sending verification code...".to_owned());
                                spawn(async move {
                                        let result = async {
                                            let (auth_base, coauth) =
                                                coauth_for_principal(principal.trim(), auth_hint.trim()).await?;
                                            let response = coauth
                                                .send_webvh_registration_email(id.trim(), mail.trim())
                                                .await?;
                                            if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                                anyhow::bail!(error);
                                            }
                                            Ok::<_, anyhow::Error>((auth_base, response))
                                        }
                                        .await;
                                        match result {
                                            Ok((auth_base, response)) => {
                                                auth_server_url.set(auth_base);
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
                                    let auth_hint = auth_server_url();
                                    let id = registration_id();
                                    let code = verification_code();
                                    is_busy.set(true);
                                    register_status.set("Verifying email...".to_owned());
                                    spawn(async move {
                                        let result = async {
                                            let (auth_base, coauth) =
                                                coauth_for_principal(principal.trim(), auth_hint.trim()).await?;
                                            let response = coauth
                                                .verify_webvh_registration_email(id.trim(), code.trim())
                                                .await?;
                                            if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                                anyhow::bail!(error);
                                            }
                                            Ok::<_, anyhow::Error>((auth_base, response))
                                        }
                                        .await;
                                        match result {
                                            Ok((auth_base, _)) => {
                                                auth_server_url.set(auth_base);
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
                                    let auth_hint = auth_server_url();
                                    let id = registration_id();
                                    let device = device_id();
                                    let name = username();
                                    let mail = email();
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
                                            let did_key = generate_webvh_key_material()?;
                                            let update_key = generate_webvh_key_material()?;
                                            let (auth_base, coauth) =
                                                coauth_for_principal(principal.trim(), auth_hint.trim()).await?;
                                            let webvh_version_time = chrono::Utc::now()
                                                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                                            let webvh_proof = build_embedded_webvh_inception_proof(
                                                principal.trim(),
                                                name.trim(),
                                                did_key.public_key_multibase.as_str(),
                                                update_key.public_key_multibase.as_str(),
                                                "did-key-1",
                                                &update_key.signing_key,
                                                webvh_version_time.as_str(),
                                            )?;
                                            let response = coauth
                                                .finish_webvh_registration(
                                                    id.trim(),
                                                    did_key.public_key_multibase.as_str(),
                                                    update_key.public_key_multibase.as_str(),
                                                    "did-key-1",
                                                    "update-key-1",
                                                    webvh_version_time.as_str(),
                                                    webvh_proof,
                                                    device.trim(),
                                                    password_value.as_str(),
                                                    password_confirm_value.as_str(),
                                                )
                                                .await?;
                                            if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                                anyhow::bail!(error);
                                            }
                                            Ok::<_, anyhow::Error>((auth_base, response, did_key, update_key))
                                        }
                                        .await;
                                        match result {
                                            Ok((auth_base, response, did_key, update_key)) => {
                                                auth_server_url.set(auth_base.clone());
                                                let did = response.did.clone();
                                                let did_public_key_multibase = response
                                                    .did_public_key_multibase
                                                    .clone()
                                                    .unwrap_or_else(|| did_key.public_key_multibase.clone());
                                                let update_public_key_multibase = response
                                                    .update_public_key_multibase
                                                    .clone()
                                                    .unwrap_or_else(|| update_key.public_key_multibase.clone());
                                                let did_seed_hex = did_key.seed_hex.clone();
                                                let update_seed_hex = update_key.seed_hex.clone();
                                                let did_public_fingerprint = did_key.fingerprint.clone();
                                                let update_public_fingerprint = update_key.fingerprint.clone();
                                                let did_key_id = response
                                                    .did_key_id
                                                    .clone()
                                                    .unwrap_or_else(|| format!("{did}#did-key-1"));
                                                let update_key_id = response
                                                    .update_key_id
                                                    .clone()
                                                    .unwrap_or_else(|| format!("{did}#update-key-1"));
                                                let provider_id = response.provider_id.clone().unwrap_or_else(|| "soland.embedded".to_owned());
                                                let key_log_head = response.key_log_head.clone().unwrap_or_else(|| "missing".to_owned());
                                                let document_url = response.document_url.clone().unwrap_or_default();
                                                let log_url = response.log_url.clone().unwrap_or_default();
                                                let created_at = chrono::Utc::now().to_rfc3339();
                                                let key_record = json!({
                                                    "kind": "cx.did_webvh.private_keys.v1",
                                                    "did": did,
                                                    "provider_id": provider_id,
                                                    "created_at": created_at,
                                                    "keys": [
                                                        {
                                                            "kind": "did_document_controller_key_seed",
                                                            "algorithm": "Ed25519",
                                                            "key_id": did_key_id,
                                                            "roles": [
                                                                "did_document.verificationMethod",
                                                                "did_document.authentication",
                                                                "did_document.assertionMethod",
                                                            ],
                                                            "public_key_multibase": did_public_key_multibase,
                                                            "public_fingerprint": did_public_fingerprint,
                                                            "encoding": "hex",
                                                            "seed_hex": did_seed_hex,
                                                        },
                                                        {
                                                            "kind": "did_webvh_update_key_seed",
                                                            "algorithm": "Ed25519",
                                                            "key_id": update_key_id,
                                                            "roles": [
                                                                "did_webvh.inception",
                                                                "did_webvh.updateKeys[0]",
                                                            ],
                                                            "public_key_multibase": update_public_key_multibase,
                                                            "public_fingerprint": update_public_fingerprint,
                                                            "encoding": "hex",
                                                            "seed_hex": update_seed_hex,
                                                        }
                                                    ],
                                                })
                                                .to_string();
                                                let backup_json = build_account_backup_json(
                                                    name.trim(),
                                                    mail.trim(),
                                                    principal.trim(),
                                                    auth_base.as_str(),
                                                    device.trim(),
                                                    did.as_str(),
                                                    did_key_id.as_str(),
                                                    update_key_id.as_str(),
                                                    provider_id.as_str(),
                                                    key_log_head.as_str(),
                                                    document_url.as_str(),
                                                    log_url.as_str(),
                                                    did_public_key_multibase.as_str(),
                                                    did_public_fingerprint.as_str(),
                                                    did_seed_hex.as_str(),
                                                    update_public_key_multibase.as_str(),
                                                    update_public_fingerprint.as_str(),
                                                    update_seed_hex.as_str(),
                                                    created_at.as_str(),
                                                );
                                                let backup_filename = account_backup_filename(name.trim(), did.as_str());
                                                state_store.write().save_private_data(
                                                    did.as_str(),
                                                    "did_webvh.private_keys.v1",
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
                                                    did_key_id,
                                                    update_key_id,
                                                    key_log_head,
                                                    provider_id,
                                                    document_url,
                                                    log_url,
                                                    did_public_key_multibase,
                                                    did_public_fingerprint,
                                                    did_private_seed_hex: did_seed_hex,
                                                    update_public_key_multibase,
                                                    update_public_fingerprint,
                                                    update_private_seed_hex: update_seed_hex,
                                                    backup_filename,
                                                    backup_json,
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
                            div { "DID key: " span { "data-testid": "register-did-key-id", "{summary.did_key_id}" } }
                            div { "Webvh update key: " span { "data-testid": "register-update-key-id", "{summary.update_key_id}" } }
                            div { "Key log head: " span { "data-testid": "register-key-log-head", "{summary.key_log_head}" } }
                            div { "Public DID key: {summary.did_public_fingerprint}" }
                            div { "Public webvh update key: {summary.update_public_fingerprint}" }
                            if !summary.document_url.is_empty() {
                                div { "Document: {summary.document_url}" }
                            }
                            if !summary.log_url.is_empty() {
                                div { "Log: {summary.log_url}" }
                            }
                            div { "DID public key material: {summary.did_public_key_multibase}" }
                            div { "Update public key material: {summary.update_public_key_multibase}" }
                            button {
                                class: "secondary auth-secondary",
                                "data-testid": "download-account-backup",
                                onclick: {
                                    let backup_filename = summary.backup_filename.clone();
                                    let backup_json = summary.backup_json.clone();
                                    move |_| {
                                        match download_text_file(backup_filename.as_str(), backup_json.as_str()) {
                                            Ok(()) => register_status.set("Account backup download started.".to_owned()),
                                            Err(error) => register_status.set(format!("Account backup download failed: {error}")),
                                        }
                                    }
                                },
                                "Download account backup"
                            }
                            details { "data-testid": "register-private-key-details",
                                summary { "Show private key seeds" }
                                div { "The DID seed signs as the current DID authentication/assertion key. The webvh update seed controls future DID document updates. Save both now; coauth and soland do not have them." }
                                div {
                                    "Private DID key seed: "
                                    span { "data-testid": "register-did-private-key-seed", "{summary.did_private_seed_hex}" }
                                }
                                div {
                                    "Private webvh update key seed: "
                                    span { "data-testid": "register-update-private-key-seed", "{summary.update_private_seed_hex}" }
                                }
                            }
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
                    button {
                        class: "primary auth-primary",
                        "data-testid": "start-existing-did-registration-button",
                        disabled: is_busy() || existing_did().trim().is_empty(),
                        onclick: move |_| {
                            let principal = base_url();
                            let auth_hint = auth_server_url();
                            let did = existing_did();
                            let device = device_id();
                            is_busy.set(true);
                            register_status.set("Starting DID binding...".to_owned());
                            spawn(async move {
                                let result = async {
                                    let (auth_base, coauth) =
                                        coauth_for_principal(principal.trim(), auth_hint.trim()).await?;
                                    let response = coauth
                                        .bind_existing_did_registration(did.trim(), device.trim())
                                        .await?;
                                    if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                        anyhow::bail!(error);
                                    }
                                    Ok::<_, anyhow::Error>((auth_base, response))
                                }
                                .await;
                                match result {
                                    Ok((auth_base, response)) => {
                                        auth_server_url.set(auth_base);
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
                            let auth_hint = auth_server_url();
                            let mail = recovery_email();
                            is_busy.set(true);
                            register_status.set("Starting recovery...".to_owned());
                            spawn(async move {
                                let result = async {
                                    let (auth_base, coauth) =
                                        coauth_for_principal(principal.trim(), auth_hint.trim()).await?;
                                    let response = coauth.start_recovery(mail.trim()).await?;
                                    if let Some(error) = api_response_error(&response.status, response.error.as_deref()) {
                                        anyhow::bail!(error);
                                    }
                                    Ok::<_, anyhow::Error>((auth_base, response))
                                }
                                .await;
                                match result {
                                    Ok((auth_base, response)) => {
                                        auth_server_url.set(auth_base);
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

async fn coauth_for_principal(
    principal_server_url: &str,
    cached_auth_server_url: &str,
) -> anyhow::Result<(String, CoauthApi)> {
    let auth_server_url = if cached_auth_server_url.trim().is_empty() {
        resolve_auth_server_url(principal_server_url).await?
    } else {
        validate_server_url(cached_auth_server_url)?.to_string()
    };
    let coauth = CoauthApi::new(&auth_server_url)?;
    Ok((auth_server_url, coauth))
}

async fn resolve_auth_server_url(principal_server_url: &str) -> anyhow::Result<String> {
    resolve_principal_auth_server_url(principal_server_url).await
}

fn api_response_error(status: &str, error: Option<&str>) -> Option<String> {
    match status {
        "ok" | "success" | "sent" | "accepted" | "pending" | "proof_required" => None,
        other => Some(error.unwrap_or(other).to_owned()),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_account_backup_json(
    username: &str,
    email: &str,
    principal_server_url: &str,
    auth_server_url: &str,
    device_id: &str,
    did: &str,
    did_key_id: &str,
    update_key_id: &str,
    provider_id: &str,
    key_log_head: &str,
    document_url: &str,
    log_url: &str,
    did_public_key_multibase: &str,
    did_public_fingerprint: &str,
    did_private_seed_hex: &str,
    update_public_key_multibase: &str,
    update_public_fingerprint: &str,
    update_private_seed_hex: &str,
    created_at: &str,
) -> String {
    serde_json::to_string_pretty(&json!({
        "kind": "cx.yougen.account_backup.v1",
        "created_at": created_at,
        "account": {
            "username": username,
            "email": email,
            "did": did,
            "device_id": device_id,
            "principal_server_url": principal_server_url,
            "auth_server_url": auth_server_url,
        },
        "did_webvh": {
            "provider_id": provider_id,
            "did_key_id": did_key_id,
            "update_key_id": update_key_id,
            "same_key_for_controller_and_update": false,
            "key_log_head": key_log_head,
            "document_url": document_url,
            "log_url": log_url,
        },
        "key_model": {
            "model": "separate_did_controller_and_webvh_update_keys",
            "current_did_private_key": did_key_id,
            "webvh_update_private_key": update_key_id,
            "same_key_material": false,
            "note": "The DID Document authentication/assertion key is separate from did:webvh updateKeys[0]."
        },
        "public_keys": [
            {
                "kind": "did_document_controller_key",
                "algorithm": "Ed25519",
                "key_id": did_key_id,
                "roles": [
                    "did_document.verificationMethod",
                    "did_document.authentication",
                    "did_document.assertionMethod"
                ],
                "public_key_multibase": did_public_key_multibase,
                "fingerprint": did_public_fingerprint,
            },
            {
                "kind": "did_webvh_update_key",
                "algorithm": "Ed25519",
                "key_id": update_key_id,
                "roles": [
                    "did_webvh.inception",
                    "did_webvh.updateKeys[0]"
                ],
                "public_key_multibase": update_public_key_multibase,
                "fingerprint": update_public_fingerprint,
            }
        ],
        "private_keys": [
            {
                "kind": "did_document_controller_key_seed",
                "algorithm": "Ed25519",
                "key_id": did_key_id,
                "roles": [
                    "did_document.verificationMethod",
                    "did_document.authentication",
                    "did_document.assertionMethod"
                ],
                "encoding": "hex",
                "seed_hex": did_private_seed_hex,
            },
            {
                "kind": "did_webvh_update_key_seed",
                "algorithm": "Ed25519",
                "key_id": update_key_id,
                "roles": [
                    "did_webvh.inception",
                    "did_webvh.updateKeys[0]"
                ],
                "encoding": "hex",
                "seed_hex": update_private_seed_hex,
            }
        ],
        "excluded_secrets": [
            "account_password"
        ],
        "recovery_notes": [
            "This file contains separate private key material for the current DID controller key and the did:webvh update key.",
            "coauth and soland do not receive or store either private seed.",
            "Store this backup in a password manager or encrypted offline storage."
        ],
    }))
    .unwrap_or_else(|_| "{}".to_owned())
}

fn account_backup_filename(username: &str, did: &str) -> String {
    let label = if username.trim().is_empty() {
        did.rsplit(':').next().unwrap_or("account")
    } else {
        username
    };
    format!(
        "contrix-account-backup-{}.json",
        sanitize_filename_component(label)
    )
}

fn sanitize_filename_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "account".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(target_arch = "wasm32")]
fn download_text_file(filename: &str, contents: &str) -> Result<(), String> {
    use wasm_bindgen::{JsCast as _, JsValue};

    let window = web_sys::window().ok_or_else(|| "browser window is unavailable".to_owned())?;
    let document = window
        .document()
        .ok_or_else(|| "browser document is unavailable".to_owned())?;
    let parts = js_sys::Array::new();
    parts.push(&JsValue::from_str(contents));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type("application/json;charset=utf-8");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &options)
        .map_err(js_value_to_string)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(js_value_to_string)?;
    let anchor = document
        .create_element("a")
        .map_err(js_value_to_string)?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| "created element is not an anchor".to_owned())?;
    anchor.set_href(&url);
    anchor.set_download(filename);
    anchor.click();
    web_sys::Url::revoke_object_url(&url).map_err(js_value_to_string)?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn download_text_file(_filename: &str, _contents: &str) -> Result<(), String> {
    Err("browser download is only available in the web app".to_owned())
}

#[cfg(target_arch = "wasm32")]
fn js_value_to_string(value: wasm_bindgen::JsValue) -> String {
    value
        .as_string()
        .unwrap_or_else(|| "browser download failed".to_owned())
}

fn generate_webvh_key_material() -> anyhow::Result<WebvhKeyMaterial> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|error| anyhow::anyhow!("rng fill: {error}"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key_multibase = encode_ed25519_did_key_multibase(&signing_key.verifying_key());
    let digest = Sha256::digest(public_key_multibase.as_bytes());
    Ok(WebvhKeyMaterial {
        signing_key,
        public_key_multibase,
        seed_hex: hex_encode(&seed),
        fingerprint: format!("sha256:{}", hex_encode(&digest[..8])),
    })
}

const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";
const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";

fn build_embedded_webvh_inception_proof(
    principal_server_url: &str,
    username: &str,
    did_public_key_multibase: &str,
    update_public_key_multibase: &str,
    did_key_fragment: &str,
    update_signing_key: &SigningKey,
    version_time: &str,
) -> anyhow::Result<Value> {
    let service_endpoint = principal_server_url.trim_end_matches('/');
    let method_authority = webvh_method_authority(service_endpoint)?;
    let local_id = normalize_webvh_local_id(username)
        .ok_or_else(|| anyhow::anyhow!("invalid webvh local id"))?;
    let did_key_fragment = normalize_webvh_key_fragment(did_key_fragment)
        .ok_or_else(|| anyhow::anyhow!("invalid webvh did key id"))?;
    let placeholder_did = embedded_webvh_did(&method_authority, WEBVH_SCID_PLACEHOLDER, &local_id);
    let did_key_id = format!("{placeholder_did}#{did_key_fragment}");
    let did_document = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": placeholder_did,
        "verificationMethod": [{
            "id": did_key_id,
            "type": "Multikey",
            "controller": placeholder_did,
            "publicKeyMultibase": did_public_key_multibase,
        }],
        "authentication": [did_key_id],
        "assertionMethod": [did_key_id],
        "alsoKnownAs": [format!("acct:{local_id}")],
        "service": [{
            "id": format!("{placeholder_did}#soland"),
            "type": "ContrixPrincipalServer",
            "serviceEndpoint": service_endpoint,
        }],
    });
    let skeleton = json!({
        "versionId": format!("0-{WEBVH_SCID_PLACEHOLDER}"),
        "versionTime": version_time,
        "parameters": {
            "scid": WEBVH_SCID_PLACEHOLDER,
            "method": WEBVH_METHOD_VERSION,
            "updateKeys": [update_public_key_multibase],
        },
        "state": did_document,
    });
    let scid = derive_webvh_scid(&skeleton)?;
    let did = embedded_webvh_did(&method_authority, &scid, &local_id);
    let mut entry = substitute_webvh_scid(skeleton, &scid);
    let version_hash = webvh_entry_hash_multibase(&entry)?;
    if let Value::Object(map) = &mut entry {
        map.insert(
            "versionId".to_owned(),
            Value::String(format!("1-{version_hash}")),
        );
    }
    let payload = contrix_sdk::canonical::canonical_json_bytes(&entry)
        .map_err(|error| anyhow::anyhow!("canonicalize webvh log entry: {error}"))?;
    let signature = update_signing_key.sign(&payload);
    Ok(json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "authentication",
        "verificationMethod": format!("{did}#{update_public_key_multibase}"),
        "proofValue": format!("z{}", bs58::encode(signature.to_bytes()).into_string()),
    }))
}

fn webvh_method_authority(principal_server_url: &str) -> anyhow::Result<String> {
    let parsed = url::Url::parse(principal_server_url)
        .map_err(|error| anyhow::anyhow!("principal server URL is invalid: {error}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("principal server URL must include a host"))?;
    if !host.contains('.') {
        anyhow::bail!("principal server URL host must contain a dot for did:webvh");
    }
    Ok(match parsed.port() {
        Some(port) => format!("{host}%3A{port}"),
        None => host.to_owned(),
    })
}

fn embedded_webvh_did(method_authority: &str, scid: &str, local_id: &str) -> String {
    format!("did:webvh:{scid}:{method_authority}:webvh:{local_id}")
}

fn derive_webvh_scid(skeleton: &Value) -> anyhow::Result<String> {
    if !contains_webvh_placeholder(skeleton) {
        anyhow::bail!("webvh inception skeleton is missing SCID placeholders");
    }
    let canonical = contrix_sdk::canonical::canonical_json_bytes(skeleton)
        .map_err(|error| anyhow::anyhow!("canonicalize webvh SCID skeleton: {error}"))?;
    Ok(sha256_multihash_multibase(&canonical))
}

fn contains_webvh_placeholder(value: &Value) -> bool {
    match value {
        Value::String(value) => value.contains(WEBVH_SCID_PLACEHOLDER),
        Value::Array(items) => items.iter().any(contains_webvh_placeholder),
        Value::Object(map) => map.values().any(contains_webvh_placeholder),
        _ => false,
    }
}

fn substitute_webvh_scid(value: Value, scid: &str) -> Value {
    let Ok(text) = serde_json::to_string(&value) else {
        return value;
    };
    serde_json::from_str(&text.replace(WEBVH_SCID_PLACEHOLDER, scid)).unwrap_or(value)
}

fn webvh_entry_hash_multibase(value: &Value) -> anyhow::Result<String> {
    let canonical =
        contrix_sdk::canonical::canonical_json_bytes(&strip_webvh_entry_for_hash(value))
            .map_err(|error| anyhow::anyhow!("canonicalize webvh entry hash: {error}"))?;
    Ok(sha256_multihash_multibase(&canonical))
}

fn strip_webvh_entry_for_hash(value: &Value) -> Value {
    let mut clone = value.clone();
    if let Value::Object(map) = &mut clone {
        map.remove("proof");
        map.remove("versionId");
    }
    clone
}

fn sha256_multihash_multibase(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12);
    multihash.push(0x20);
    multihash.extend_from_slice(&digest);
    format!("z{}", bs58::encode(multihash).into_string())
}

fn normalize_webvh_local_id(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('@').to_ascii_lowercase();
    let valid = !normalized.is_empty()
        && normalized.len() <= 64
        && !normalized.contains("..")
        && normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    valid.then_some(normalized)
}

fn normalize_webvh_key_fragment(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('#').to_owned();
    let valid = !normalized.is_empty()
        && normalized.len() <= 64
        && normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    valid.then_some(normalized)
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
