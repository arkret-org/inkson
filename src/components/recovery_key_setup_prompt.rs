//! Inline Recovery Key setup prompt used by encryption onboarding.
//!
//! This is intentionally a modal flow instead of a settings-page redirect:
//! users choosing recommended encryption need the single required action
//! directly in context, namely generating and saving the 24-word Recovery Key.

use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::recovery_crypto::generate_recovery_key;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;

fn begin_recovery_key_setup(
    base_url: Signal<String>,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
    mut generated_recovery_key: Signal<String>,
    mut status: Signal<String>,
    mut copied: Signal<bool>,
    on_server_configured: Option<EventHandler<()>>,
) {
    let recovery_key = match generate_recovery_key() {
        Ok(key) => key,
        Err(err) => {
            status.set(format!("Recovery Key generation failed: {err}"));
            return;
        }
    };
    let actor = account_did();
    let mut store = state_store;
    if crate::views::recovery::save_generated_recovery_key_metadata(
        &mut store,
        &actor,
        &recovery_key,
    )
    .is_none()
    {
        status.set("Recovery Key generated, but local metadata could not be saved.".to_owned());
        return;
    }
    copied.set(false);
    generated_recovery_key.set(recovery_key.clone());
    status.set(
        "Recovery Key generated. Write down all 24 words now; they are shown only in this prompt."
            .to_owned(),
    );
    crate::views::recovery::upload_recovery_key_account_backup(
        base_url(),
        token,
        account_did,
        device_id,
        state_store,
        recovery_key,
        status,
        on_server_configured,
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
    let mut auto_generate_started = use_signal(|| false);

    use_effect(move || {
        if !open() {
            auto_generate_started.set(false);
            generated_recovery_key.set(String::new());
            status.set(String::new());
            copied.set(false);
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
            status,
            copied,
            on_server_configured,
        );
    });

    if !open() {
        return rsx! {};
    }

    let generated_now = generated_recovery_key();
    let current_status = status();
    let generation_failed = generated_now.trim().is_empty()
        && (current_status.contains("failed") || current_status.contains("could not be saved"));

    rsx! {
        div {
            class: "modal-overlay recovery-key-setup-overlay",
            "data-testid": "recovery-key-setup-modal",
            role: "presentation",
            onclick: move |_| {
                if generated_recovery_key().trim().is_empty() {
                    open.set(false);
                } else {
                    status.set(
                        "Store these 24 words first, then use the saved confirmation button."
                            .to_owned(),
                    );
                }
            },
            div {
                class: "modal event mls-recovery-modal mls-backup-banner recovery-key-setup-dialog",
                role: "dialog",
                "aria-modal": "true",
                "aria-labelledby": "recovery-key-setup-title",
                "aria-label": "Set up 24-word Recovery Key",
                "data-testid": "recovery-key-setup-banner",
                onclick: move |event: dioxus::events::MouseEvent| {
                    event.stop_propagation();
                },
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
                    div { class: "muted",
                        "Generate the 24 words here, write them down offline, then continue with encrypted Realms. Cokret cannot recover these words for you."
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
                                        let localpart =
                                            crate::components::mls_backup_prompt::recovery_localpart_from_handles(
                                                &personal_handles(),
                                            );
                                        let filename =
                                            crate::components::mls_backup_prompt::recovery_key_filename(&localpart);
                                        move |_| {
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
                        }
                    }
                    if !current_status.is_empty() {
                        div { class: "muted", "data-testid": "recovery-key-setup-status", "{current_status}" }
                    }
                }
                div { class: "modal-foot mls-backup-row",
                    if generated_now.trim().is_empty() {
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
                                        status,
                                        copied,
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
                            variant: ButtonVariant::Primary,
                            "data-testid": "recovery-key-setup-saved",
                            onclick: {
                                let saved_recovery_key = generated_now.clone();
                                move |_| {
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
                                    open.set(false);
                                }
                            },
                            "I saved these 24 words"
                        }
                    }
                }
            }
        }
    }
}
