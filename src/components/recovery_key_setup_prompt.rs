//! Inline Recovery Key setup prompt used by encryption onboarding.
//!
//! This is intentionally a modal strand instead of a settings-page redirect:
//! users choosing recommended encryption need the single required action
//! directly in context, namely generating and saving the 24-word Recovery Key.

use dioxus::prelude::*;
use dioxus_router::hooks::use_navigator;

use crate::recovery_crypto::{
    RecoveryKeyConfirmationDiff, generate_recovery_key, recovery_key_confirmation_diff,
};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::recovery::RecoveryKeyBackupOutcome;

/// Prepare a recovery secret for explicit cold-custody confirmation.
///
/// The words are revealed before any recovery-policy or backup write. The
/// caller may publish recovery material only after the user re-enters the same
/// phrase; no plaintext or encrypted copy is persisted as ordinary device
/// state while confirmation is pending.
fn begin_recovery_key_setup(
    account_did: Signal<String>,
    mut generated_recovery_key: Signal<String>,
    mut confirmation_input: Signal<String>,
    mut status: Signal<String>,
    mut copied: Signal<bool>,
    mut device_unauthorized: Signal<bool>,
) {
    if account_did().trim().is_empty() {
        status.set("Recovery Key setup requires an active account.".to_owned());
        return;
    }
    let recovery_key = match generate_recovery_key() {
        Ok(key) => key,
        Err(err) => {
            status.set(format!("Recovery Key generation failed: {err}"));
            return;
        }
    };
    copied.set(false);
    confirmation_input.set(String::new());
    device_unauthorized.set(false);
    generated_recovery_key.set(recovery_key);
    status.set(
        "Write the 24 words down offline, then re-enter them. Nothing has been published yet."
            .to_owned(),
    );
}
#[component]
pub fn RecoveryKeySetupPrompt(
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    open: Signal<bool>,
    account_primary_handle: Signal<String>,
    #[props(default)] on_server_configured: Option<EventHandler<()>>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let session = crate::app::SessionContext::get();
    let base_url = session.base_url;
    let mut state_store = session.state_store;
    let mut generated_recovery_key = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut copied = use_signal(|| false);
    let mut confirmation_input = use_signal(String::new);
    let mut auto_generate_started = use_signal(|| false);
    let mut device_unauthorized = use_signal(|| false);
    let mut publishing = use_signal(|| false);
    let navigator = use_navigator();

    use_effect(move || {
        if !open() {
            auto_generate_started.set(false);
            generated_recovery_key.set(String::new());
            confirmation_input.set(String::new());
            status.set(String::new());
            copied.set(false);
            device_unauthorized.set(false);
            publishing.set(false);
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
            account_did,
            generated_recovery_key,
            confirmation_input,
            status,
            copied,
            device_unauthorized,
        );
    });

    if !open() {
        return rsx! {};
    }

    let generated_now = generated_recovery_key();
    let confirmation_now = confirmation_input();
    let current_status = status();
    let is_device_unauthorized = device_unauthorized();
    let is_publishing = publishing();
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
                role: "dialog",
                "aria-modal": "true",
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
                            "This device isn't authorized to publish recovery material. The words remain only on this screen; authorize the device, then retry with the same confirmed key, or restore with the existing Recovery Key."
                        }
                    } else {
                        div { class: "muted",
                            "Generate the 24 words here, write them down offline, then continue with encrypted Realms. Arkret cannot recover these words for you."
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
                                            let primary_handle = account_primary_handle();
                                            let filename =
                                                crate::components::mls_backup_prompt::recovery_key_filename_from_handles(
                                                    std::slice::from_ref(&primary_handle),
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
                                        account_did,
                                        generated_recovery_key,
                                        confirmation_input,
                                        status,
                                        copied,
                                        device_unauthorized,
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
                            disabled: is_publishing,
                            onclick: move |_| {
                                auto_generate_started.set(true);
                                status.set("Generating a replacement Recovery Key...".to_owned());
                                begin_recovery_key_setup(
                                    account_did,
                                    generated_recovery_key,
                                    confirmation_input,
                                    status,
                                    copied,
                                    device_unauthorized,
                                );
                            },
                            "Generate a new key"
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "recovery-key-setup-saved",
                            disabled: confirmation_now.trim().is_empty() || is_publishing,
                            onclick: {
                                let saved_recovery_key = generated_now.clone();
                                move |_| {
                                    if publishing() {
                                        return;
                                    }
                                    match recovery_key_confirmation_diff(
                                        &saved_recovery_key,
                                        &confirmation_input(),
                                    ) {
                                        RecoveryKeyConfirmationDiff::Match => {}
                                        RecoveryKeyConfirmationDiff::WordCount { entered } => {
                                            status.set(format!(
                                                "You entered {entered} of 24 words. Complete the phrase, then confirm again."
                                            ));
                                            return;
                                        }
                                        RecoveryKeyConfirmationDiff::MismatchAt { index } => {
                                            status.set(format!(
                                                "Word {index} does not match this Recovery Key. Fix it and confirm again."
                                            ));
                                            return;
                                        }
                                    }
                                    let actor = account_did();
                                    if actor.trim().is_empty()
                                        || saved_recovery_key.trim().is_empty()
                                    {
                                        status.set(
                                            "Recovery Key setup requires an active account."
                                                .to_owned(),
                                        );
                                        return;
                                    }
                                    status.set(
                                        "Cold custody confirmed. Publishing the recovery policy and first encrypted backup…"
                                            .to_owned(),
                                    );
                                    publishing.set(true);
                                    let accepted_key = saved_recovery_key.clone();
                                    let accepted_actor = actor.clone();
                                    let on_outcome = EventHandler::new(
                                        move |outcome: RecoveryKeyBackupOutcome| match outcome {
                                            RecoveryKeyBackupOutcome::Established => {
                                                let mut store_signal = state_store;
                                                let Some((fingerprint, _)) =
                                                    crate::views::recovery::save_generated_recovery_key_metadata(
                                                        &mut store_signal,
                                                        &accepted_actor,
                                                        &accepted_key,
                                                    )
                                                    else {
                                                    publishing.set(false);
                                                    status.set(
                                                        "Recovery material was accepted, but public local metadata could not be saved."
                                                            .to_owned(),
                                                    );
                                                    return;
                                                };
                                                let mut store = state_store.write();
                                                store.save_private_data(
                                                    &accepted_actor,
                                                    crate::app::RECOVERY_AUTO_PROMPT_SHOWN_KEY,
                                                    "1".to_owned(),
                                                );
                                                store.save_private_data(
                                                    &accepted_actor,
                                                    crate::app::RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY,
                                                    fingerprint,
                                                );
                                                generated_recovery_key.set(String::new());
                                                confirmation_input.set(String::new());
                                                open.set(false);
                                            }
                                            RecoveryKeyBackupOutcome::DeviceNotAuthorized => {
                                                publishing.set(false);
                                                device_unauthorized.set(true);
                                            }
                                            RecoveryKeyBackupOutcome::Transient => {
                                                publishing.set(false);
                                            }
                                        },
                                    );
                                    crate::views::recovery::upload_recovery_key_account_backup(
                                        base_url(),
                                        token,
                                        account_did,
                                        device_id,
                                        state_store,
                                        saved_recovery_key.clone(),
                                        status,
                                        on_server_configured,
                                        Some(on_outcome),
                                    );
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
