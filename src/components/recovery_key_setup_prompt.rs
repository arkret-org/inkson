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
    principal_id: Signal<String>,
    mut generated_recovery_key: Signal<String>,
    mut confirmation_input: Signal<String>,
    mut status: Signal<String>,
    mut copied: Signal<bool>,
    mut device_unauthorized: Signal<bool>,
    mut generation_failed: Signal<bool>,
) {
    generation_failed.set(false);
    if principal_id().trim().is_empty() {
        status.set(crate::i18n::tr("recovery_setup.err_requires_account"));
        return;
    }
    let recovery_key = match generate_recovery_key() {
        Ok(key) => key,
        Err(err) => {
            generation_failed.set(true);
            status.set(crate::i18n::tr_args(
                "recovery_setup.err_generation_failed",
                &[("error", err.to_string())],
            ));
            return;
        }
    };
    copied.set(false);
    confirmation_input.set(String::new());
    device_unauthorized.set(false);
    generated_recovery_key.set(recovery_key);
    status.set(crate::i18n::tr("recovery_setup.status_after_generate"));
}
#[component]
pub fn RecoveryKeySetupPrompt(
    token: Signal<String>,
    principal_id: Signal<String>,
    device_id: Signal<String>,
    open: Signal<bool>,
    account_primary_handle: Signal<String>,
    #[props(default)] on_server_configured: Option<EventHandler<()>>,
) -> Element {
    let session = crate::app::SessionContext::get();
    let active_account = session.active_account;
    let mut state_store = session.state_store;
    let mut generated_recovery_key = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut copied = use_signal(|| false);
    let mut confirmation_input = use_signal(String::new);
    let mut auto_generate_started = use_signal(|| false);
    let mut device_unauthorized = use_signal(|| false);
    let mut publishing = use_signal(|| false);
    // Tracks generation failure explicitly; the status text is localized, so
    // string-matching it would break in non-English locales.
    let mut generation_failed = use_signal(|| false);
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
            generation_failed.set(false);
            return;
        }
        if auto_generate_started()
            || !generated_recovery_key().trim().is_empty()
            || principal_id().trim().is_empty()
        {
            return;
        }
        auto_generate_started.set(true);
        status.set(crate::i18n::tr("recovery_setup.generating"));
        begin_recovery_key_setup(
            principal_id,
            generated_recovery_key,
            confirmation_input,
            status,
            copied,
            device_unauthorized,
            generation_failed,
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
    let has_generation_failed = generation_failed() && generated_now.trim().is_empty();

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
                    status.set(crate::i18n::tr("recovery_setup.save_first_guard"));
                }
            },
            "data-testid": "recovery-key-setup-modal",
            "aria-labelledby": "recovery-key-setup-title",
            "aria-label": crate::i18n::tr("recovery_setup.aria_label"),
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
                            status.set(crate::i18n::tr("recovery_setup.save_first_guard"));
                        }
                    }
                },
                div { class: "modal-head event-head",
                    h3 { id: "recovery-key-setup-title", {crate::i18n::tr("recovery_setup.title")} }
                    span { class: "muted", {crate::i18n::tr("recovery_setup.subtitle")} }
                }
                div { class: "modal-body mls-recovery-modal-body",
                    if is_device_unauthorized {
                        div { class: "form-hint-warn", "data-testid": "recovery-key-setup-device-unauthorized",
                            {crate::i18n::tr("recovery_setup.device_unauthorized")}
                        }
                    } else {
                        div { class: "muted",
                            {crate::i18n::tr("recovery_setup.intro")}
                        }
                    }
                    if !generated_now.trim().is_empty() {
                        div { class: "workflow-form",
                            Label { html_for: "recovery-key-setup-generated-key",
                                {crate::i18n::tr("recovery_setup.generated_key_label")}
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
                                        {crate::i18n::tr("recovery_setup.copied")}
                                    } else {
                                        {crate::i18n::tr("recovery_setup.copy_words")}
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
                                    {crate::i18n::tr("recovery_setup.download")}
                                }
                            }
                            div { class: "form-hint-warn", "data-testid": "recovery-key-setup-generated-key-warning",
                                {crate::i18n::tr("recovery_setup.save_warning")}
                            }
                            Label { html_for: "recovery-key-setup-confirm-key",
                                {crate::i18n::tr("recovery_setup.confirm_label")}
                            }
                            Textarea {
                                id: "recovery-key-setup-confirm-key",
                                "data-testid": "recovery-key-setup-confirm-key",
                                rows: "3",
                                value: "{confirmation_now}",
                                placeholder: crate::i18n::tr("recovery_setup.confirm_placeholder"),
                                oninput: move |event: FormEvent| confirmation_input.set(event.value()),
                            }
                            div { class: "muted", "data-testid": "recovery-key-setup-confirm-hint",
                                {crate::i18n::tr("recovery_setup.confirm_hint")}
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
                            {crate::i18n::tr("recovery_setup.restore_button")}
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "recovery-key-setup-dismiss",
                            onclick: move |_| open.set(false),
                            {crate::i18n::tr("recovery_setup.close")}
                        }
                    } else if generated_now.trim().is_empty() {
                        if has_generation_failed {
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "recovery-key-setup-submit",
                                onclick: move |_| {
                                    auto_generate_started.set(true);
                                    status.set(crate::i18n::tr("recovery_setup.generating"));
                                    begin_recovery_key_setup(
                                        principal_id,
                                        generated_recovery_key,
                                        confirmation_input,
                                        status,
                                        copied,
                                        device_unauthorized,
                                        generation_failed,
                                    );
                                },
                                {crate::i18n::tr("recovery_setup.try_again")}
                            }
                        } else {
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "recovery-key-setup-loading",
                                disabled: true,
                                {crate::i18n::tr("recovery_setup.generating_button")}
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "recovery-key-setup-dismiss",
                            onclick: move |_| open.set(false),
                            {crate::i18n::tr("recovery_setup.not_now")}
                        }
                    } else {
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "recovery-key-setup-regenerate",
                            disabled: is_publishing,
                            onclick: move |_| {
                                auto_generate_started.set(true);
                                status.set(crate::i18n::tr("recovery_setup.generating_replacement"));
                                begin_recovery_key_setup(
                                    principal_id,
                                    generated_recovery_key,
                                    confirmation_input,
                                    status,
                                    copied,
                                    device_unauthorized,
                                    generation_failed,
                                );
                            },
                            {crate::i18n::tr("recovery_setup.regenerate")}
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
                                            status.set(crate::i18n::tr_args(
                                                "recovery_setup.err_word_count",
                                                &[("entered", entered.to_string())],
                                            ));
                                            return;
                                        }
                                        RecoveryKeyConfirmationDiff::MismatchAt { index } => {
                                            status.set(crate::i18n::tr_args(
                                                "recovery_setup.err_word_mismatch",
                                                &[("index", index.to_string())],
                                            ));
                                            return;
                                        }
                                    }
                                    let actor = principal_id();
                                    if actor.trim().is_empty()
                                        || saved_recovery_key.trim().is_empty()
                                    {
                                        status.set(crate::i18n::tr(
                                            "recovery_setup.err_requires_account",
                                        ));
                                        return;
                                    }
                                    let principal_id = account.principal_id().to_string();
                                    status.set(crate::i18n::tr("recovery_setup.publishing"));
                                    publishing.set(true);
                                    let accepted_key = saved_recovery_key.clone();
                                    let accepted_principal_id = principal_id.clone();
                                    let on_outcome = EventHandler::new(
                                        move |outcome: RecoveryKeyBackupOutcome| match outcome {
                                            RecoveryKeyBackupOutcome::Established => {
                                                let mut store_signal = state_store;
                                                let Some((fingerprint, _)) =
                                                    crate::views::recovery::save_generated_recovery_key_metadata(
                                                        &mut store_signal,
                                                        &accepted_principal_id,
                                                        &accepted_key,
                                                    )
                                                    else {
                                                    publishing.set(false);
                                                    status.set(crate::i18n::tr(
                                                        "recovery_setup.metadata_save_failed",
                                                    ));
                                                    return;
                                                };
                                                let mut store = state_store.write();
                                                store.save_private_data(
                                                    &accepted_principal_id,
                                                    crate::app::RECOVERY_AUTO_PROMPT_SHOWN_KEY,
                                                    "1".to_owned(),
                                                );
                                                store.save_private_data(
                                                    &accepted_principal_id,
                                                    crate::app::RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY,
                                                    fingerprint,
                                                );
                                                generated_recovery_key.set(String::new());
                                                confirmation_input.set(String::new());
                                                open.set(false);
                                            }
                                            RecoveryKeyBackupOutcome::DeviceUnauthorized => {
                                                publishing.set(false);
                                                device_unauthorized.set(true);
                                            }
                                            RecoveryKeyBackupOutcome::Transient => {
                                                publishing.set(false);
                                            }
                                        },
                                    );
                                    crate::views::recovery::upload_recovery_key_account_backup(
                                        token,
                                        principal_id,
                                        device_id,
                                        state_store,
                                        saved_recovery_key.clone(),
                                        status,
                                        on_server_configured,
                                        Some(on_outcome),
                                    );
                                }
                            },
                            {crate::i18n::tr("recovery_setup.confirm_button")}
                        }
                    }
                }
            }
        }
    }
}
