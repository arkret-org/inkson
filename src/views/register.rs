//! Account creation entry point.
//!
//! Service-account policy, passwords, passkeys and email verification belong
//! to the Account Authority. Inkson starts the same canonical OIDC handoff and
//! performs principal custody only after the callback.

use std::rc::Rc;

use glory::{Cage, Scope};

use crate::presentation::{InksonContext, View};
use crate::views::settings::widgets::*;

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

fn begin(
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    busy: Cage<bool>,
    feedback: Cage<RegistrationFeedback>,
) {
    if busy.get_untracked() {
        return;
    }
    let station = context.base_url;
    let state_store = context.state_store.clone();
    let action = move |_| {
        let server = station.get();
        let ui_locale = context.locale.get().code().to_owned();
        // This route is the explicit new-identity intent.  A
        // device identity belongs to one principal, so it must
        // never inherit the active/previous account's id.
        let device = crate::config::new_device_id();
        busy.revise(|value| *value = true);
        feedback.revise(|value| *value = RegistrationFeedback::Progress);
        if let Some(scope) = owner.upgrade() {
            spawn(&scope, async move {
                let result = async {
                    let device = arkret_sdk::DeviceId::new(device)?;
                    #[cfg(target_arch = "wasm32")]
                    let secure_store = {
                        tracing::info!(
                            target: "account_onboarding",
                            device_id = %device,
                            "create identity: waiting for IndexedDB secure store"
                        );
                        let store =
                            crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
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
                    let pending_store =
                        crate::secure_key_store::PendingLocalStore::new(device.clone());
                    pending_store
                        .save_device_id_durable(secure_store.as_ref())
                        .await?;
                    tracing::info!(
                        target: "account_onboarding",
                        device_id = %device,
                        "create identity: bootstrap device persisted; opening authority"
                    );
                    let prepared_authorization = crate::views::login::prepare_oidc_authorization(
                        &server,
                        device.as_str(),
                        crate::identity::account_auth::OidcEntryPoint::CreateIdentity,
                        None,
                        None,
                        &ui_locale,
                    )
                    .await
                    .map_err(anyhow::Error::msg)?;

                    // The authentication route already fenced the previous session.
                    state_store.write(|store| store.begin_pending_login(&device, None));
                    crate::secure_key_store::reset_device_seed_scope_for_signin(
                        secure_store.as_ref(),
                        &device,
                    )?;
                    state_store.write(|store| store.set_dpop_device_key(None));
                    pending_store.activate();
                    tracing::info!(
                        target: "account_onboarding",
                        device_id = %device,
                        "create identity: pending login established; opening authority"
                    );
                    prepared_authorization
                        .launch()
                        .map_err(anyhow::Error::msg)?;
                    Ok(())
                }
                .await;
                if let Err(error) = result {
                    tracing::error!(
                        target: "account_onboarding",
                        error = %error,
                        "create identity: account authority handoff failed"
                    );
                    feedback.revise(|value| {
                        *value = RegistrationFeedback::Error(registration_failure(&error))
                    });
                    busy.revise(|value| *value = false);
                }
            });
        };
    };
    action(());
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

pub fn page(scope: &Scope, context: Rc<InksonContext>, _route: crate::routes::Route) -> View {
    let busy = scope.cage(false);
    let feedback = scope.cage(RegistrationFeedback::default());
    let station = context.base_url;
    let status_context = context.clone();
    let status = reactive(feedback, move |scope, feedback| {
        let context = status_context.clone();
        match feedback {
            RegistrationFeedback::Idle => empty(),
            RegistrationFeedback::Progress => {
                paragraph("auth-status", context.translated(scope, "register.opening"))
            }
            RegistrationFeedback::Error(failure) => {
                let show = scope.cage(false);
                let detail = failure.technical_detail;
                let details = reactive(show, move |_, open| {
                    if open {
                        paragraph("mono", detail.clone())
                    } else {
                        empty()
                    }
                });
                stack(
                    "auth-error",
                    vec![
                        plain("!"),
                        stack(
                            "auth-error-content",
                            vec![
                                heading(3, "", registration_error_title(failure.kind)),
                                paragraph("", registration_error_guidance(failure.kind)),
                                action(
                                    scope,
                                    context,
                                    "register-error-details",
                                    "register.error.technical_details",
                                    "secondary",
                                    true,
                                    move || show.revise(|value| *value = !*value),
                                ),
                                details,
                            ],
                        ),
                    ],
                )
            }
        }
    });
    let owner = scope.downgrade();
    let begin_context = context.clone();
    let sign_in = context.clone();
    stack(
        "auth-panel registration-panel",
        vec![
            line(
                "auth-brand",
                vec![
                    plain("C"),
                    stack(
                        "",
                        vec![heading(1, "", "Create account"), paragraph("", "Arkret")],
                    ),
                ],
            ),
            stack(
                "auth-form",
                vec![
                    status,
                    input(
                        scope,
                        context.clone(),
                        "register-server",
                        "Station",
                        station,
                        scope.bond(move || !busy.get()),
                    ),
                    action(
                        scope,
                        context.clone(),
                        "register-open-account-authority",
                        "login.continue",
                        "primary",
                        scope.bond(move || !busy.get()),
                        move || begin(begin_context.clone(), owner.clone(), busy, feedback),
                    ),
                    stack(
                        "auth-footer",
                        vec![action(
                            scope,
                            context,
                            "register-sign-in",
                            "Already have an account? Sign in",
                            "secondary",
                            true,
                            move || sign_in.navigate(crate::routes::Route::Login),
                        )],
                    ),
                ],
            ),
        ],
    )
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
