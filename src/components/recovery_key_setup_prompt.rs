//! Inline Recovery Key setup prompt used by encryption onboarding.
//!
//! This is intentionally a modal strand instead of a settings-page redirect:
//! users choosing recommended encryption need the single required action
//! directly in context, namely generating and saving the 24-word Recovery Key.

use dioxus::prelude::*;
use dioxus_router::hooks::use_navigator;

use crate::local_state::LocalStateStore;
use crate::recovery_crypto::{generate_recovery_key, recovery_key_confirmation_matches};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::recovery::RecoveryKeyBackupOutcome;

/// Fail-closed Recovery Key establishment.
///
/// Security invariant: a device may only establish (reveal + locally persist) a
/// brand-new account Recovery Key root if the SERVER first confirms this device
/// is an authorized, verified key-management device for the account. So we:
///
/// 1. generate the 24 words **in memory only** — nothing persisted, nothing shown;
/// 2. attempt the server backup (`upload_recovery_key_account_backup`, which now persists local
///    metadata ONLY on success);
/// 3. reveal the words and mark recovery configured **only** on `Established`;
/// 4. on `DeviceNotAuthorized` discard the key and route the user to authorize this device /
///    restore with their existing Recovery Key — never leave a divergent root behind.
fn begin_recovery_key_setup(
    base_url: Signal<String>,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
    mut generated_recovery_key: Signal<String>,
    mut confirmation_input: Signal<String>,
    mut status: Signal<String>,
    mut copied: Signal<bool>,
    mut device_unauthorized: Signal<bool>,
    on_server_configured: Option<EventHandler<()>>,
) {
    let recovery_key = match generate_recovery_key() {
        Ok(key) => key,
        Err(err) => {
            status.set(format!("Recovery Key generation failed: {err}"));
            return;
        }
    };
    if account_did().trim().is_empty() {
        status.set("Recovery Key setup requires an active account.".to_owned());
        return;
    }
    copied.set(false);
    confirmation_input.set(String::new());
    device_unauthorized.set(false);
    generated_recovery_key.set(String::new());
    status.set("Authorizing this device and publishing the recovery backup…".to_owned());
    // Reveal/persist gating happens entirely on the server outcome. Built within
    // component scope (this fn is only ever called from a use_effect / onclick),
    // so EventHandler::new is valid here.
    let reveal_key = recovery_key.clone();
    let on_outcome = EventHandler::new(move |outcome: RecoveryKeyBackupOutcome| match outcome {
        RecoveryKeyBackupOutcome::Established => {
            generated_recovery_key.set(reveal_key.clone());
        }
        RecoveryKeyBackupOutcome::DeviceNotAuthorized => {
            generated_recovery_key.set(String::new());
            device_unauthorized.set(true);
        }
        RecoveryKeyBackupOutcome::Transient => {
            generated_recovery_key.set(String::new());
        }
    });
    crate::views::recovery::upload_recovery_key_account_backup(
        base_url(),
        token,
        account_did,
        device_id,
        state_store,
        recovery_key,
        status,
        on_server_configured,
        Some(on_outcome),
    );
}

#[component]
pub fn RecoveryKeySetupPrompt(
    base_url: Signal<String>,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
    open: Signal<bool>,
    personal_handles: Signal<Vec<String>>,
    #[props(default)] on_server_configured: Option<EventHandler<()>>,
) -> Element {
    let mut generated_recovery_key = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut copied = use_signal(|| false);
    let mut confirmation_input = use_signal(String::new);
    let mut auto_generate_started = use_signal(|| false);
    let mut device_unauthorized = use_signal(|| false);
    let navigator = use_navigator();

    use_effect(move || {
        if !open() {
            auto_generate_started.set(false);
            generated_recovery_key.set(String::new());
            confirmation_input.set(String::new());
            status.set(String::new());
            copied.set(false);
            device_unauthorized.set(false);
            return;
        }
        if auto_generate_started()
            || !generated_recovery_key().trim().is_empty()
            || account_did().trim().is_empty()
        {
            return;
        }
        auto_generate_started.set(true);
        status.set("Generating Recovery Key...".to_owned());
        begin_recovery_key_setup(
            base_url,
            token,
            account_did,
            device_id,
            state_store,
            generated_recovery_key,
            confirmation_input,
            status,
            copied,
            device_unauthorized,
            on_server_configured,
        );
    });

    if !open() {
        return rsx! {};
    }

    let generated_now = generated_recovery_key();
    let confirmation_now = confirmation_input();
    let current_status = status();
    let is_device_unauthorized = device_unauthorized();
    let generation_failed = !is_device_unauthorized
        && generated_now.trim().is_empty()
        && (current_status.contains("failed") || current_status.contains("could not be saved"));

    rsx! {
        Dialog {
            open: true,
            on_open_change: move |next_open: bool| {
                if next_open {
                    return;
                }
                if generated_recovery_key().trim().is_empty() {
                    open.set(false);
                } else {
                    status.set(
                        "Store these 24 words first, then use the saved confirmation button."
                            .to_owned(),
                    );
                }
            },
            "data-testid": "recovery-key-setup-modal",
            "aria-labelledby": "recovery-key-setup-title",
            "aria-label": "Set up 24-word Recovery Key",
            div {
                class: "modal event mls-recovery-modal mls-backup-banner recovery-key-setup-dialog",
                "data-testid": "recovery-key-setup-banner",
                onkeydown: move |event: dioxus::events::KeyboardEvent| {
                    if event.key().to_string() == "Escape" {
                        event.prevent_default();
                        event.stop_propagation();
                        if generated_recovery_key().trim().is_empty() {
                            open.set(false);
                        } else {
                            status.set(
                                "Store these 24 words first, then use the saved confirmation button."
                                    .to_owned(),
                            );
                        }
                    }
                },
                div { class: "modal-head event-head",
                    h3 { id: "recovery-key-setup-title", "Set up your 24-word Recovery Key" }
                    span { class: "muted", "required before encryption" }
                }
                div { class: "modal-body mls-recovery-modal-body",
                    if is_device_unauthorized {
                        div { class: "form-hint-warn", "data-testid": "recovery-key-setup-device-unauthorized",
                            "This device isn't authorized to create the account Recovery Key. Authorize it from a device you already use, or restore with your existing 24-word Recovery Key. A new key is never created on an unverified device."
                        }
                    } else {
                        div { class: "muted",
                            "Generate the 24 words here, write them down offline, then continue with encrypted Realms. Cokret cannot recover these words for you."
                        }
                    }
                    if !generated_now.trim().is_empty() {
                        div { class: "workflow-form",
                            Label { html_for: "recovery-key-setup-generated-key",
                                "Recovery Key (24 words)"
                            }
                            Textarea {
                                id: "recovery-key-setup-generated-key",
                                "data-testid": "recovery-key-setup-generated-key",
                                rows: "3",
                                readonly: true,
                                value: "{generated_now}",
                            }
                            div { class: "mls-backup-key-actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "recovery-key-setup-copy-key",
                                    onclick: {
                                        let key = generated_now.clone();
                                        move |_| {
                                            crate::components::mls_backup_prompt::copy_text_to_clipboard(&key);
                                            copied.set(true);
                                        }
                                    },
                                    if copied() {
                                        "Copied"
                                    } else {
                                        "Copy words"
                                    }
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "recovery-key-setup-download-key",
                                    onclick: {
                                        let key = generated_now.clone();
                                        move |_| {
                                            let filename =
                                                crate::components::mls_backup_prompt::recovery_key_filename_from_handles(
                                                    &personal_handles(),
                                                );
                                            crate::components::mls_backup_prompt::download_text_as_file(
                                                &filename,
                                                &key,
                                            );
                                        }
                                    },
                                    "Download .txt"
                                }
                            }
                            div { class: "form-hint-warn", "data-testid": "recovery-key-setup-generated-key-warning",
                                "Store these words now. The plaintext Recovery Key is not uploaded and will not be shown again after you close this prompt."
                            }
                            Label { html_for: "recovery-key-setup-confirm-key",
                                "Re-enter the saved Recovery Key"
                            }
                            Textarea {
                                id: "recovery-key-setup-confirm-key",
                                "data-testid": "recovery-key-setup-confirm-key",
                                rows: "3",
                                value: "{confirmation_now}",
                                placeholder: "Type or paste the 24 words you saved",
                                oninput: move |event: FormEvent| confirmation_input.set(event.value()),
                            }
                            div { class: "muted", "data-testid": "recovery-key-setup-confirm-hint",
                                "You can continue only after the saved copy matches exactly. If the copy is wrong, generate a new key and save that one instead."
                            }
                        }
                    }
                    if !current_status.is_empty() {
                        div { class: "muted", "data-testid": "recovery-key-setup-status", "{current_status}" }
                    }
                }
                div { class: "modal-foot mls-backup-row",
                    if is_device_unauthorized {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "recovery-key-setup-restore",
                            onclick: move |_| {
                                open.set(false);
                                navigator.push(crate::routes::Route::Recovery);
                            },
                            "Restore with existing Recovery Key"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "recovery-key-setup-dismiss",
                            onclick: move |_| open.set(false),
                            "Close"
                        }
                    } else if generated_now.trim().is_empty() {
                        if generation_failed {
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "recovery-key-setup-submit",
                                onclick: move |_| {
                                    auto_generate_started.set(true);
                                    status.set("Generating Recovery Key...".to_owned());
                                    begin_recovery_key_setup(
                                        base_url,
                                        token,
                                        account_did,
                                        device_id,
                                        state_store,
                                        generated_recovery_key,
                                        confirmation_input,
                                        status,
                                        copied,
                                        device_unauthorized,
                                        on_server_configured,
                                    );
                                },
                                "Try again"
                            }
                        } else {
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "recovery-key-setup-loading",
                                disabled: true,
                                "Generating..."
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "recovery-key-setup-dismiss",
                            onclick: move |_| open.set(false),
                            "Not now"
                        }
                    } else {
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "recovery-key-setup-regenerate",
                            onclick: move |_| {
                                auto_generate_started.set(true);
                                status.set("Generating a replacement Recovery Key...".to_owned());
                                begin_recovery_key_setup(
                                    base_url,
                                    token,
                                    account_did,
                                    device_id,
                                    state_store,
                                    generated_recovery_key,
                                    confirmation_input,
                                    status,
                                    copied,
                                    device_unauthorized,
                                    on_server_configured,
                                );
                            },
                            "Generate a new key"
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "recovery-key-setup-saved",
                            disabled: confirmation_now.trim().is_empty(),
                            onclick: {
                                let saved_recovery_key = generated_now.clone();
                                move |_| {
                                    if !recovery_key_confirmation_matches(
                                        &saved_recovery_key,
                                        &confirmation_input(),
                                    ) {
                                        status.set(
                                            "The entered words do not match this Recovery Key. Check your saved copy, or generate a new key and save that one instead."
                                                .to_owned(),
                                        );
                                        return;
                                    }
                                    let actor = account_did();
                                    if !actor.trim().is_empty()
                                        && !saved_recovery_key.trim().is_empty()
                                    {
                                        let fingerprint =
                                            crate::recovery_crypto::fingerprint_recovery_key(
                                                &saved_recovery_key,
                                            );
                                        let mut store = state_store.write();
                                        store.save_private_data(
                                            &actor,
                                            crate::app::RECOVERY_AUTO_PROMPT_SHOWN_KEY,
                                            "1".to_owned(),
                                        );
                                        store.save_private_data(
                                            &actor,
                                            crate::app::RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY,
                                            fingerprint,
                                        );
                                    }
                                    generated_recovery_key.set(String::new());
                                    confirmation_input.set(String::new());
                                    open.set(false);
                                }
                            },
                            "Confirm saved key"
                        }
                    }
                }
            }
        }
    }
}
