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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum RegistrationFeedback {
    #[default]
    Idle,
    Progress,
    Error(RegistrationFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RegistrationFailure {
    kind: RegistrationFailureKind,
    technical_detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistrationFailureKind {
    InvalidServerAddress,
    ServiceUnavailable,
    Unexpected,
}

#[component]
pub fn RegistrationPanel(mut token: Signal<String>) -> Element {
    let mut principal_server = crate::app::SessionContext::get().base_url;
    let mut state_store = crate::app::SessionContext::get().state_store;
    let session = use_context::<crate::runtime::services::RuntimeServices>().session;
    let i18n = use_context::<crate::i18n::I18nSignal>();
    let mut busy = use_signal(|| false);
    let mut feedback = use_signal(RegistrationFeedback::default);
    let feedback_value = feedback();

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
                if matches!(feedback_value, RegistrationFeedback::Progress) {
                    div {
                        class: "auth-status",
                        role: "status",
                        "aria-live": "polite",
                        {crate::i18n::tr("register.opening")}
                    }
                }
                if let RegistrationFeedback::Error(failure) = &feedback_value {
                    div {
                        class: "auth-error",
                        role: "alert",
                        "aria-live": "assertive",
                        div { class: "auth-error-mark", "aria-hidden": "true", "!" }
                        div { class: "auth-error-content",
                            strong { {registration_error_title(failure.kind)} }
                            p { {registration_error_guidance(failure.kind)} }
                            details {
                                summary { {crate::i18n::tr("register.error.technical_details")} }
                                code { "{failure.technical_detail}" }
                            }
                        }
                    }
                }
                Label { html_for: "register-server", "Principal server" }
                Input {
                    id: "register-server",
                    "data-testid": "register-server",
                    value: "{principal_server}",
                    disabled: busy(),
                    oninput: move |event: FormEvent| principal_server.set(event.value()),
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
                        // Explicit registration starts a transaction-scoped
                        // anonymous namespace. Stop the live session, but keep
                        // last-known account/device configuration unchanged
                        // until the new identity commits successfully.
                        session.invalidate("starting a new-account registration transaction");
                        token.set(String::new());
                        busy.set(true);
                        feedback.set(RegistrationFeedback::Progress);
                        spawn(async move {
                            let result = async {
                                #[cfg(target_arch = "wasm32")]
                                let secure_store = {
                                    tracing::info!(
                                        target: "account_onboarding",
                                        device_id = %device,
                                        "create identity: waiting for IndexedDB secure store"
                                    );
                                    let store = crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
                                        .await
                                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                                    tracing::info!(
                                        target: "account_onboarding",
                                        backend = store.backend_name(),
                                        device_id = %device,
                                        "create identity: secure store ready"
                                    );
                                    store
                                };
                                #[cfg(not(target_arch = "wasm32"))]
                                let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                                state_store.write().begin_pending_login(device.trim(), None);
                                crate::secure_key_store::reset_device_seed_scope_for_signin(
                                    secure_store.as_ref(),
                                )?;
                                tracing::info!(
                                    target: "account_onboarding",
                                    device_id = %device,
                                    "create identity: bootstrap key scope reset"
                                );
                                state_store.write().set_dpop_device_key(None);
                                tracing::info!(
                                    target: "account_onboarding",
                                    device_id = %device,
                                    "create identity: pending login established"
                                );
                                let pending_store = crate::secure_key_store::PendingLocalStore::new(
                                    arkret_sdk::DeviceId::new(device.trim().to_owned())?,
                                );
                                pending_store.activate();
                                pending_store
                                    .save_device_id_durable(secure_store.as_ref())
                                    .await?;
                                tracing::info!(
                                    target: "account_onboarding",
                                    device_id = %device,
                                    "create identity: bootstrap device persisted; opening authority"
                                );
                                crate::views::login::start_oidc_strand(
                                    &server,
                                    device.trim(),
                                    crate::identity::account_auth::OidcEntryPoint::CreateIdentity,
                                    None,
                                    None,
                                    &ui_locale,
                                )
                                .await
                                .map_err(anyhow::Error::msg)
                            }
                            .await;
                            if let Err(error) = result {
                                tracing::error!(
                                    target: "account_onboarding",
                                    error = %error,
                                    "create identity: account authority handoff failed"
                                );
                                feedback.set(RegistrationFeedback::Error(
                                    registration_failure(&error),
                                ));
                                busy.set(false);
                            }
                        });
                    },
                    {crate::i18n::tr("login.continue")}
                }
                div { class: "auth-footer",
                    Link { to: crate::routes::Route::Login, "Already have an account? Sign in" }
                }
            }
        }
    }
}

fn registration_failure(error: &anyhow::Error) -> RegistrationFailure {
    let detail = error.to_string().to_ascii_lowercase();
    let kind = if detail.contains("invalid url") || detail.contains("relative url") {
        RegistrationFailureKind::InvalidServerAddress
    } else if detail.contains("service unavailable")
        || detail.contains("temporarily unavailable")
        || detail.contains("status was 503")
    {
        RegistrationFailureKind::ServiceUnavailable
    } else {
        RegistrationFailureKind::Unexpected
    };
    RegistrationFailure {
        kind,
        technical_detail: error.to_string(),
    }
}

fn registration_error_title(kind: RegistrationFailureKind) -> String {
    crate::i18n::tr(match kind {
        RegistrationFailureKind::InvalidServerAddress => "register.error.invalid_server.title",
        RegistrationFailureKind::ServiceUnavailable => "register.error.unavailable.title",
        RegistrationFailureKind::Unexpected => "register.error.unexpected.title",
    })
}

fn registration_error_guidance(kind: RegistrationFailureKind) -> String {
    crate::i18n::tr(match kind {
        RegistrationFailureKind::InvalidServerAddress => "register.error.invalid_server.guidance",
        RegistrationFailureKind::ServiceUnavailable => "register.error.unavailable.guidance",
        RegistrationFailureKind::Unexpected => "register.error.unexpected.guidance",
    })
}

#[cfg(test)]
mod tests {
    use super::{RegistrationFailureKind, registration_failure};

    #[test]
    fn registration_errors_separate_user_message_from_protocol_diagnostics() {
        let unavailable = anyhow::anyhow!(
            "OIDC discovery remained unavailable after 60 seconds (13 attempts); last status was 503 Service Unavailable"
        );
        let failure = registration_failure(&unavailable);
        assert_eq!(failure.kind, RegistrationFailureKind::ServiceUnavailable);
        assert!(failure.technical_detail.contains("OIDC"));
        assert!(failure.technical_detail.contains("503"));
    }
}
