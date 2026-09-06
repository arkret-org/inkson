//! Account-first identity setup.
//!
//! The user-facing flow intentionally hides the handoff lease, DID inception,
//! PCR genesis, and recovery-material gate. Those protocol stages remain
//! durable and resumable, but the page presents only three user decisions:
//! choose an identity, save its Recovery Key, and finish.

use dioxus::prelude::*;
use dioxus_router::Link;
use dioxus_router::hooks::use_navigator;

use crate::components::QrSharePanel;
use crate::recovery_crypto::{RecoveryKeyConfirmationDiff, recovery_key_confirmation_diff};
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

mod account_commit;
mod controller;
mod device_pairing;
mod flow_state;
mod identity_setup;
mod resume;
#[cfg(test)]
mod tests;

use account_commit::*;
use controller::*;
use device_pairing::*;
use flow_state::*;
use identity_setup::*;
use resume::*;

const CURRENT_DEPLOYMENT_HUMAN_ANCHOR_METHOD: &str = "did:webvh";

#[derive(Clone, Debug, PartialEq, Eq)]
enum ServerReconciliationStatus {
    Loading,
    Ready,
    Failed(String),
}

#[component]
pub fn OnboardingPanel(
    secure_store_ready: bool,
    token: Signal<String>,
    principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    account_primary_handle: Signal<String>,
    needs_device_authorization: Signal<bool>,
    device_authorization_check_complete: Signal<bool>,
) -> Element {
    let session_context = crate::app::SessionContext::get();
    let state_store = session_context.state_store;
    if !secure_store_ready {
        return rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                div { class: "event onboarding-card",
                    h2 { "Restoring identity setup" }
                    p { class: "muted", "Reading this account's current server state…" }
                }
            }
        };
    }
    let mut server_reconciliation = use_signal(|| ServerReconciliationStatus::Loading);
    use_effect(move || {
        let should_refresh = state_store
            .peek()
            .pending_account_handoff()
            .is_some_and(|handoff| {
                handoff.retry_after_ms.is_none()
                    && (handoff.lease_id.is_some() || handoff.bound_principal_id.is_some())
            });
        if !should_refresh {
            server_reconciliation.set(ServerReconciliationStatus::Ready);
            return;
        }
        spawn(async move {
            match crate::identity::account_auth::refresh_pending_onboarding(state_store).await {
                Ok(()) => server_reconciliation.set(ServerReconciliationStatus::Ready),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "failed to reconcile onboarding from Account Authority snapshot"
                    );
                    server_reconciliation
                        .set(ServerReconciliationStatus::Failed(format!("{error:#}")));
                }
            }
        });
    });
    // Clone the small status value before rendering. Holding a Signal read
    // guard while the reconciliation task publishes its result causes Dioxus'
    // single-threaded RefCell to panic instead of scheduling a rerender.
    let reconciliation_status = server_reconciliation();
    match &reconciliation_status {
        ServerReconciliationStatus::Loading => {
            return rsx! {
                div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                    div { class: "event onboarding-card",
                        h2 { "Checking identity setup" }
                        p { class: "muted", "Loading the current Account Authority state…" }
                    }
                }
            };
        }
        ServerReconciliationStatus::Failed(error) => {
            return rsx! {
                div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                    div { class: "event onboarding-card onboarding-centered", "data-testid": "onboarding-reconciliation-failed",
                        h2 { "Identity setup could not be refreshed" }
                        p { class: "muted", "No local checkpoint was used to guess a next step." }
                        p { class: "error", "{error}" }
                        Link { class: "primary", to: Route::Login, "Authenticate again" }
                    }
                }
            };
        }
        ServerReconciliationStatus::Ready => {}
    }
    // The durable stages are routing inputs ONLY at mount, and the decision is
    // latched for the lifetime of this mount.
    //
    // Subscribing the parent to the state store made every durable stage write
    // re-route the surface. Latching additionally survives a parent re-render
    // while the single server-authoritative continuation advances, so the
    // component holding the in-memory Recovery Key is not unmounted midway.
    // A real remount first refreshes the server snapshot and validates any
    // retained key before selecting this same continuation again.
    //
    // `routed` is only ever `peek`ed, so latching it during render notifies no
    // subscriber and cannot loop. An explicit discard bumps `reroute` (which IS
    // subscribed) to force exactly one re-decision.
    let mut routed = use_signal(|| None::<OnboardingSurface>);
    let mut reroute = use_signal(|| 0_u32);
    let _routing_generation = reroute();

    let latched = *routed.peek();
    let surface = match latched {
        Some(surface) => surface,
        None => {
            let surface = {
                let store = state_store.peek();
                onboarding_surface(
                    store.pending_account_handoff().as_ref(),
                    store.pending_principal_registration().as_ref(),
                )
            };
            routed.set(Some(surface));
            surface
        }
    };

    let on_discard = move |()| {
        routed.set(None);
        reroute += 1;
    };
    match surface {
        OnboardingSurface::DeviceSetupRequired => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                DeviceSetupRequired {
                    state_store,
                    token,
                    principal_id,
                    device_id,
                    config_store,
                    needs_device_authorization,
                    device_authorization_check_complete,
                }
            }
        },
        OnboardingSurface::IdentityCreation => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                PendingAccountIdentityCreation {
                    token,
                    principal_id,
                    device_id,
                    config_store,
                    account_primary_handle,
                    needs_device_authorization,
                    device_authorization_check_complete,
                }
            }
        },
        OnboardingSurface::StaleCheckpoint => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                StalePrincipalSetup { on_discard }
            }
        },
        OnboardingSurface::ServerStateConflict => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                div { class: "event onboarding-card onboarding-centered", "data-testid": "onboarding-server-state-conflict",
                    h2 { "Identity setup state could not be verified" }
                    p { class: "muted",
                        "The Account Authority returned an inconsistent setup checkpoint. Local data was not used to guess the next step."
                    }
                    Link { class: "primary", to: Route::Login, "Authenticate again" }
                }
            }
        },
        OnboardingSurface::AccountSummary => {
            let did = principal_id();
            let did = crate::app::principal_id_owned(did);
            let principal_label = short_protocol_id(&did);
            let complete = account_summary_complete(!token().trim().is_empty(), &did);
            rsx! {
                div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                    div { class: "event onboarding-card onboarding-finished", "data-testid": "account-strand",
                        if !complete {
                            div { class: "onboarding-finish-mark", "aria-hidden": "true", "1" }
                            h2 { "Set up your identity" }
                            p { class: "muted", "Sign in first, then choose whether to create or link an identity." }
                            Link { class: "primary", to: Route::Login, "Sign in" }
                        } else {
                            div { class: "onboarding-finish-mark", "aria-hidden": "true", "✓" }
                            h2 { "You're all set" }
                            p { class: "muted", "Your account is linked to {principal_label}." }
                            Link { class: "primary", to: Route::Dashboard, "Continue" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn DeviceSetupRequired(
    state_store: SyncSignal<crate::state::LocalStateStore>,
    token: Signal<String>,
    mut principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    mut device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    needs_device_authorization: Signal<bool>,
    device_authorization_check_complete: Signal<bool>,
) -> Element {
    let mut recovery_selected = use_signal(|| false);
    let pairing_request = use_signal(|| None::<DeviceSetupPairingRequest>);
    let mut pairing_status = use_signal(String::new);
    let mut pairing_busy = use_signal(|| false);
    let controller = DevicePairingController {
        busy: pairing_busy,
        status: pairing_status,
        request: pairing_request,
    };
    let handoff = state_store.read().pending_account_handoff();
    let recovery_device_id = handoff
        .as_ref()
        .map(|handoff| handoff.device_id.clone())
        .unwrap_or_default();
    if recovery_selected() {
        return rsx! {
            PcrPolicyDeviceRecovery {
                state_store,
                token,
                principal_id,
                device_id,
                config_store,
                replacement_device_id: recovery_device_id,
                needs_device_authorization,
                device_authorization_check_complete,
            }
        };
    }
    let request = pairing_request.read().clone();
    let qr_svg = request.as_ref().map_or_else(String::new, |request| {
        qrcode::QrCode::with_error_correction_level(
            request.deep_link.as_bytes(),
            qrcode::EcLevel::M,
        )
        .map(|code| {
            code.render::<qrcode::render::svg::Color<'_>>()
                .min_dimensions(192, 192)
                .quiet_zone(true)
                .build()
        })
        .unwrap_or_default()
    });
    rsx! {
        div { class: "event onboarding-card", "data-testid": "device-setup-required",
            h2 { "Authorize this device" }
            p { class: "muted",
                "This account is already linked, but this browser has no currently accepted device key. Generate a pairing QR code or link, then scan or open it on an already-authorized device."
            }
            p { class: "muted",
                "This server-mediated flow does not send a notification or open a prompt on your other devices. Login alone cannot authorize a new device, and no session was issued."
            }
            if handoff.as_ref().is_some_and(|handoff| handoff.bound_principal_id.is_some()) {
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "device-setup-pairing-start",
                    disabled: pairing_busy(),
                    onclick: move |_| {
                        let Some(handoff) = state_store.read().pending_account_handoff() else {
                            pairing_status.set("The authenticated account handoff is missing. Sign in again.".to_owned());
                            return;
                        };
                        pairing_busy.set(true);
                        pairing_status.set("Generating a device pairing QR code…".to_owned());
                            controller.start(handoff);
                    },
                    if pairing_busy() { "Preparing…" } else { "Generate pairing QR" }
                }
            } else {
                p { class: "error", "The bound-account handoff is incomplete. No device flow was started." }
            }
            if let Some(request) = request {
                div { class: "device-pair-approval-code-block",
                    span { class: "muted", "Compare this code before approving" }
                    span {
                        class: "device-pair-approval-code mono",
                        "data-testid": "device-setup-pairing-code",
                        "{request.pairing_code}"
                    }
                }
                QrSharePanel {
                    qr_svg,
                    url: request.deep_link.clone(),
                    qr_aria_label: "Device pairing QR code".to_owned(),
                    url_aria_label: "Device pairing link".to_owned(),
                    qr_test_id: "device-setup-pairing-qr".to_owned(),
                    url_test_id: "device-setup-pairing-link".to_owned(),
                    copy_test_id: "device-setup-pairing-copy".to_owned(),
                    url_rows: 4,
                }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "device-setup-pairing-status",
                    disabled: pairing_busy(),
                    onclick: move |_| {
                        let Some(handoff) = state_store.read().pending_account_handoff() else {
                            pairing_status.set("The authenticated account handoff is missing. Sign in again.".to_owned());
                            return;
                        };
                        let Some(request) = pairing_request.read().clone() else {
                            pairing_status.set("Generate a pairing QR first.".to_owned());
                            return;
                        };
                        pairing_busy.set(true);
                        pairing_status.set("Checking device authorization…".to_owned());
                            controller.check(handoff, request);
                    },
                    if pairing_busy() { "Checking…" } else { "Check authorization status" }
                }
            }
            if !pairing_status().is_empty() {
                p { class: "muted", role: "status", "data-testid": "device-setup-status", "{pairing_status}" }
            }
            Link { class: "secondary", to: Route::Login, "Sign in again after approval" }
            Button {
                variant: ButtonVariant::Ghost,
                "data-testid": "device-setup-use-recovery-key",
                onclick: move |_| {
                    // The 24-word surface opens only from this explicit
                    // secondary choice, and only after the bound handoff
                    // already reached a typed admission outcome.
                    let handoff = state_store.read().pending_account_handoff();
                    let (correlation, bound, no_returning_device) = handoff.as_ref().map_or_else(
                        || {
                            (
                                crate::identity::account_auth::transition::LoginCorrelation::default(),
                                false,
                                false,
                            )
                        },
                        |handoff| {
                            (
                                crate::identity::account_auth::transition::LoginCorrelation::for_handoff(handoff),
                                handoff.bound_principal_id.is_some(),
                                matches!(
                                    handoff.bound_device_entry_state.as_ref(),
                                    Some(crate::state::BoundDeviceEntryState::NoReturningDevice)
                                ),
                            )
                        },
                    );
                    if crate::identity::account_auth::transition::record_recovery_surface_opened(
                        crate::identity::account_auth::transition::RecoveryEntryReason::UserSelectedInDeviceSetup,
                        &correlation,
                        bound,
                        no_returning_device,
                    ) {
                        recovery_selected.set(true);
                    } else {
                        pairing_status.set(
                            "This account's sign-in has no authoritative device decision yet, so Recovery Key entry stays closed. Sign in again and retry device approval."
                                .to_owned(),
                        );
                    }
                },
                "Use Recovery Key instead"
            }
        }
    }
}

#[component]
fn PcrPolicyDeviceRecovery(
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    mut token: Signal<String>,
    mut principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    mut device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    replacement_device_id: String,
    mut needs_device_authorization: Signal<bool>,
    mut device_authorization_check_complete: Signal<bool>,
) -> Element {
    let session_context = crate::app::SessionContext::get();
    let active_account = session_context.active_account;
    let session_generation = session_context.session_generation;
    let completion_session = use_context::<crate::runtime::services::RuntimeServices>()
        .session
        .clone();
    let mut words = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let controller = PcrRecoveryController {
        busy,
        status,
        words,
        state_store: session_context.state_store,
        token,
        principal_id,
        device_id,
        config_store,
        active_account,
        session_generation,
        needs_device_authorization,
        device_authorization_check_complete,
    };
    rsx! {
        div { class: "event onboarding-card", "data-testid": "pcr-policy-device-recovery",
            h2 { "Recover this identity" }
            p { class: "muted",
                "This account already has an identity. Enter its 24-word Recovery Key to prove root control and authorize this device. No approval from another device or administrator is required."
            }
            Label { html_for: "root-recovery-words", "Recovery Key (24 words)" }
            Textarea {
                id: "root-recovery-words",
                value: words(),
                rows: 4,
                autocomplete: "off",
                oninput: move |event: FormEvent| words.set(event.value()),
            }
            Button {
                variant: ButtonVariant::Primary,
                disabled: busy() || words().split_whitespace().count() != 24,
                onclick: move |_| {
                    let Some(handoff) = state_store.read().pending_account_handoff() else {
                        status.set("The authenticated account recovery checkpoint is missing. Sign in again.".to_owned());
                        return;
                    };
                    let Some(principal_did) = handoff.bound_principal_did.clone() else {
                        status.set("This account does not require existing-identity recovery.".to_owned());
                        return;
                    };
                    let recovery_words = words();
                    let replacement_device_id = replacement_device_id.clone();
                    let session = completion_session.clone();
                    busy.set(true);
                    status.set("Verifying Recovery Key and preparing a PCR-policy device recovery…".to_owned());
                    controller.recover_device(
                        handoff,
                        principal_did,
                        recovery_words,
                        replacement_device_id,
                        session,
                    );
                },
                if busy() { "Recovering…" } else { "Authorize this device" }
            }
            if !status().is_empty() {
                p { class: "muted", role: "status", "{status}" }
            }
        }
    }
}

#[component]
fn SetupProgress(current: usize) -> Element {
    rsx! {
        ol { class: "onboarding-progress", "aria-label": "Setup progress",
            for (index, label) in ["Identity", "Recovery Key", "Ready"].iter().enumerate() {
                li {
                    class: if index + 1 == current {
                        "is-current"
                    } else if index + 1 < current {
                        "is-complete"
                    } else {
                        ""
                    },
                    span { class: "onboarding-progress-index", if index + 1 < current { "✓" } else { "{index + 1}" } }
                    span { "{label}" }
                }
            }
        }
    }
}

#[component]
fn PendingAccountIdentityCreation(
    mut token: Signal<String>,
    mut principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    mut device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    account_primary_handle: Signal<String>,
    mut needs_device_authorization: Signal<bool>,
    mut device_authorization_check_complete: Signal<bool>,
) -> Element {
    let session_context = crate::app::SessionContext::get();
    let active_account = session_context.active_account;
    let state_store = session_context.state_store;
    let session_generation = session_context.session_generation;
    let completion_session = use_context::<crate::runtime::services::RuntimeServices>()
        .session
        .clone();
    let initial_handoff = state_store.peek().pending_account_handoff();
    let initial_checkpoint = state_store.peek().pending_principal_registration();
    let initial_recovery_key = initial_handoff
        .as_ref()
        .and_then(|handoff| load_valid_retained_recovery_key(handoff, initial_checkpoint.as_ref()));
    let initial_key_source = RecoveryKeySource::for_initial_handoff(
        initial_handoff.as_ref(),
        initial_recovery_key.is_some(),
    );
    let initial_recovery_key_state = if initial_recovery_key.is_some() {
        arkret_sdk::IdentityCreationRecoveryKeyState::RecoveredPendingConfirmation
    } else {
        arkret_sdk::IdentityCreationRecoveryKeyState::Unavailable
    };
    let navigator = use_navigator();
    let initial_choice =
        initial_identity_choice(initial_handoff.as_ref(), initial_recovery_key.is_some());
    let mut choice = use_signal(move || initial_choice);
    let mut recovery_key = use_signal(|| initial_recovery_key.unwrap_or_default());
    let mut recovery_key_state = use_signal(|| initial_recovery_key_state);
    let mut confirmation = use_signal(String::new);
    let mut copied = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let complete = use_signal(|| false);
    let mut status = use_signal(String::new);
    let mut resume_terminal = use_signal(|| None::<ResumeTerminal>);
    // Never derive this from a later server phase in this mount. The server
    // remains authoritative for protocol progress; this signal only records
    // whether the in-memory key was generated here or must be supplied after
    // an actual reload/restart.
    let key_source = use_signal(|| initial_key_source);
    let controller = IdentityCreationController {
        busy,
        status,
        recovery_key,
        recovery_key_state,
        confirmation,
        complete,
        resume_terminal,
        state_store,
        config_store,
        active_account,
        token,
        session_generation,
        principal_id,
        device_id,
        needs_device_authorization,
        device_authorization_check_complete,
    };

    // Completion clears the durable handoff/checkpoint. Render the success
    // surface from component-local state before reading either checkpoint so
    // their cleanup cannot transiently (or permanently, if the scoped task is
    // cancelled) turn the final onboarding page into an empty node.
    if complete() {
        return rsx! {
            div { class: "event onboarding-card", "data-testid": "account-handoff-onboarding",
                SetupProgress { current: 3 }
                div { class: "onboarding-finished", "data-testid": "onboarding-complete",
                    div { class: "onboarding-finish-mark", "aria-hidden": "true", "✓" }
                    h2 { "Identity ready" }
                    p { class: "muted", "Your account, this device, and recovery backup are ready." }
                    if !status().is_empty() {
                        div { class: "form-hint-warn", role: "status", "{status}" }
                    }
                    Link { class: "primary", to: Route::Dashboard, "Continue" }
                }
            }
        };
    }

    if let Some(terminal) = resume_terminal() {
        let heading = match terminal.kind {
            ResumeTerminalKind::HydrationFailed => "Setup state could not be read",
            ResumeTerminalKind::RetryableFailure => "Setup continuation did not finish",
            ResumeTerminalKind::ReauthRequired => "Setup needs authentication",
            ResumeTerminalKind::StrandedIdentity => "This accepted identity cannot continue here",
            ResumeTerminalKind::Contradiction => "Setup state is inconsistent",
        };
        let can_retry = matches!(
            terminal.kind,
            ResumeTerminalKind::HydrationFailed | ResumeTerminalKind::RetryableFailure
        );
        let can_clear = matches!(
            terminal.kind,
            ResumeTerminalKind::StrandedIdentity | ResumeTerminalKind::Contradiction
        );
        return rsx! {
            div {
                class: "event onboarding-card onboarding-centered",
                "data-testid": "onboarding-resume-diagnostics",
                h2 { "{heading}" }
                p { class: "muted", "{terminal.reason}" }
                ul { class: "muted", "data-testid": "onboarding-resume-inventory",
                    for item in terminal.inventory.iter() {
                        li { "{item}" }
                    }
                }
                div { class: "onboarding-footer-actions",
                    if can_retry {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "retry-onboarding-resume",
                            onclick: move |_| {
                                resume_terminal.set(None);
                                status.set(String::new());
                            },
                            if terminal.kind == ResumeTerminalKind::HydrationFailed {
                                "Retry storage check"
                            } else {
                                "Retry exact continuation"
                            }
                        }
                    }
                    if terminal.kind == ResumeTerminalKind::ReauthRequired {
                        Link { class: "primary", to: Route::Login, "Sign in again" }
                    }
                    if can_clear {
                        Link { class: "secondary", to: Route::Login, "Sign in another account" }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "clear-stranded-onboarding",
                            disabled: busy(),
                            onclick: move |_| {
                                let navigator = navigator;
                                busy.set(true);
                                controller.clear_stranded_setup(navigator);
                            },
                            if terminal.kind == ResumeTerminalKind::StrandedIdentity {
                                "Abandon this setup and register a new identity"
                            } else {
                                "Clear this setup"
                            }
                        }
                    }
                }
                if !status().is_empty() {
                    div { class: "form-hint-warn", role: "status", "{status}" }
                }
            }
        };
    }

    let handoff = state_store.read().pending_account_handoff();

    let Some(handoff) = handoff else {
        let did = principal_id();
        let did = crate::app::principal_id_owned(did);
        let fallback = missing_creation_handoff_surface(busy(), !token().trim().is_empty(), &did);
        let current_status = status();
        return rsx! {
            div {
                class: "event onboarding-card onboarding-centered",
                "data-testid": "onboarding-missing-account-handoff",
                match fallback {
                    MissingCreationHandoffSurface::Finishing => rsx! {
                        SetupProgress { current: 3 }
                        h2 { "Finishing identity setup" }
                        p { class: "muted", "The account binding was accepted. Inkson is finishing the local recovery and session records…" }
                        if !current_status.is_empty() {
                            div { class: "muted", role: "status", "{current_status}" }
                        }
                    },
                    MissingCreationHandoffSurface::Complete => rsx! {
                        SetupProgress { current: 3 }
                        div { class: "onboarding-finished", "data-testid": "onboarding-complete",
                            div { class: "onboarding-finish-mark", "aria-hidden": "true", "✓" }
                            h2 { "Identity ready" }
                            p { class: "muted", "Your account, this device, and recovery backup are ready." }
                            Link { class: "primary", to: Route::Dashboard, "Continue" }
                        }
                    },
                    MissingCreationHandoffSurface::SignInRequired => rsx! {
                        h2 { "Identity setup needs authentication" }
                        p { class: "muted", "The previous account handoff is no longer available. Sign in again so Inkson can resume from the current Account Authority state." }
                        if !current_status.is_empty() {
                            div { class: "form-hint-warn", role: "status", "{current_status}" }
                        }
                        Link { class: "primary", to: Route::Login, "Sign in again" }
                    },
                }
            }
        };
    };
    let pending_abandonment = handoff.identity_abandonment.clone().or_else(|| {
        state_store
            .read()
            .pending_principal_registration()
            .and_then(|checkpoint| checkpoint.identity_abandonment)
    });
    let abandonment_challenge_expired = pending_abandonment
        .as_ref()
        .is_some_and(|pending| pending.challenge.expires_at <= chrono::Utc::now());
    let abandonment_confirmation_ready = pending_abandonment.as_ref().is_some_and(|pending| {
        crate::identity::identity_abandonment::has_fresh_confirmation_handoff(&handoff, pending)
    });

    if let Some(retry_after_ms) = handoff.retry_after_ms {
        let retry_after_seconds = retry_after_ms.div_ceil(1_000).max(1);
        return rsx! {
            div { class: "event onboarding-card onboarding-centered", "data-testid": "identity-creation-busy",
                h2 { "Setup is already in progress" }
                p { class: "muted", "Continue in the open setup, or wait about {retry_after_seconds} seconds and then sign in again on this device." }
                Link { class: "secondary", to: Route::Login, "Sign in again" }
            }
        };
    }

    let expired = handoff.expires_at <= chrono::Utc::now()
        || handoff
            .lease_expires_at
            .is_some_and(|expires_at| expires_at <= chrono::Utc::now());
    if expired {
        return rsx! {
            div { class: "event onboarding-card onboarding-centered", "data-testid": "account-handoff-expired",
                h2 { "Setup expired" }
                p { class: "muted", "Sign in again so Inkson can recalculate the flow from the current server state. A matching Recovery Key retained in this device's secure store will be re-confirmed; otherwise Inkson will ask for the original key or offer explicit abandonment." }
                Link { class: "primary", to: Route::Login, "Sign in again" }
            }
        };
    }

    let current_step = if choice() == IdentityChoice::Create {
        2
    } else {
        1
    };
    let hosting_name = hosting_label(&handoff.station_url);
    let resumes_reserved_identity = key_source.peek().requires_existing_key();
    let reoffers_retained_key = key_source.peek().was_recovered_from_secure_store();
    let handoff_for_creation = handoff.clone();
    let handoff_for_abandonment = handoff.clone();

    rsx! {
        div { class: "event onboarding-card", "data-testid": "account-handoff-onboarding",
            SetupProgress { current: current_step }

            if let Some(pending_abandonment) = pending_abandonment {
                div { class: "onboarding-heading",
                    span { class: "eyebrow", "Explicit abandonment" }
                    h2 { "Confirm giving up this provisional identity" }
                    p { class: "muted",
                        "The orphan anchor will be permanently unusable and cannot be deactivated or continued. A new identity root DID and PCR must be created."
                    }
                }
                div { class: "callout warn",
                    div { class: "body",
                        strong { "This cannot be undone." }
                        " Confirm only after re-authenticating the account."
                    }
                }
                div { class: "onboarding-footer-actions",
                    Link { class: "secondary", to: Route::Login, "Authenticate again" }
                    if abandonment_challenge_expired {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "restart-identity-abandonment-challenge",
                            disabled: busy(),
                            onclick: move |_| {
                                let Some(handoff) = state_store.read().pending_account_handoff() else {
                                    status.set("Authenticate the account again before renewing the abandonment challenge.".to_owned());
                                    return;
                                };
                                busy.set(true);
                                status.set("Renewing explicit abandonment challenge…".to_owned());
                                controller.renew_abandonment_challenge(handoff);
                            },
                            if busy() { "Renewing…" } else { "Renew expired challenge" }
                        }
                    } else {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "confirm-identity-abandonment",
                            disabled: busy() || !abandonment_confirmation_ready,
                            onclick: move |_| {
                                let Some(handoff) = state_store.read().pending_account_handoff() else {
                                    status.set("Authenticate the account again before confirming abandonment.".to_owned());
                                    return;
                                };
                                let pending = pending_abandonment.clone();
                                let navigator = navigator;
                                busy.set(true);
                                status.set("Confirming explicit abandonment…".to_owned());
                                controller.confirm_abandonment(handoff, pending, navigator);
                            },
                            if busy() { "Confirming…" } else { "Permanently abandon identity" }
                        }
                    }
                }
                if !status().is_empty() {
                    div { class: "form-hint-warn", role: "status", "{status}" }
                }
            } else if choice() == IdentityChoice::Choose {
                div { class: "onboarding-heading",
                    if resumes_reserved_identity {
                        h2 { "An identity reservation is unfinished" }
                        p { class: "muted", "The server has an unfinished identity reservation. That does not mean Inkson knows you saved its Recovery Key. Enter the original key if you still have it, or explicitly abandon this reservation before creating another identity." }
                    } else {
                        h2 { "Set up your identity" }
                        p { class: "muted", "Inkson creates one identity for this account and authorizes this device as its first device." }
                    }
                }

                div { class: "identity-choice-grid", role: "group", "aria-label": "Identity setup",
                    section { class: "identity-choice-card is-recommended",
                        if resumes_reserved_identity {
                            h3 { "Verify the original Recovery Key" }
                            p { "The reserved identity is hosted with {hosting_name}. Inkson does not infer key possession from the reservation; it will verify the original key locally before continuing." }
                        } else {
                            h3 { "Create your identity" }
                            p { "It will be anchored by a Recovery Key and hosted with {hosting_name}. No device approval step is needed." }
                            p { class: "muted", "This deployment creates a {CURRENT_DEPLOYMENT_HUMAN_ANCHOR_METHOD} identity. Arkret also permits did:web and did:key human anchors in deployments that support them; they are not registration options here." }
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "choose-new-identity",
                            onclick: move |_| {
                                choice.set(IdentityChoice::Create);
                                if !resumes_reserved_identity && recovery_key().is_empty() {
                                    match crate::recovery_crypto::generate_recovery_key() {
                                        Ok(key) => {
                                            recovery_key.set(key);
                                            recovery_key_state.set(
                                                arkret_sdk::IdentityCreationRecoveryKeyState::GeneratedPendingConfirmation,
                                            );
                                            confirmation.set(String::new());
                                            copied.set(false);
                                            status.set(String::new());
                                        }
                                        Err(error) => status.set(format!(
                                            "Could not create a Recovery Key: {error}"
                                        )),
                                    }
                                }
                            },
                            if resumes_reserved_identity { "Enter existing key" } else { "Continue" }
                        }
                    }
                }
                if !status().is_empty() {
                    div { class: "form-hint-warn", role: "alert", "{status}" }
                }
            } else {
                div { class: "onboarding-heading",
                    if resumes_reserved_identity {
                        h2 { "Enter your existing Recovery Key" }
                        p { class: "muted", "Inkson cannot replace the key that controls this reserved identity. If it is lost, use the explicit abandonment action below." }
                    } else if reoffers_retained_key {
                        h2 { "Re-confirm your Recovery Key" }
                        p { class: "muted", "This device securely retained the same 24 words from the unfinished setup. Re-confirm them before continuing; their presence here does not mean Inkson assumes you memorized or backed them up." }
                    } else {
                        h2 { "Save your Recovery Key" }
                        p { class: "muted", "Write down these 24 words in order. They will not be shown again." }
                    }
                }

                if !resumes_reserved_identity {
                    RecoveryKeyWords { recovery_key: recovery_key() }

                    div { class: "onboarding-key-actions",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "onboarding-copy-recovery-key",
                            onclick: {
                                let key = recovery_key();
                                move |_| {
                                    crate::components::mls_backup_prompt::copy_text_to_clipboard(&key);
                                    copied.set(true);
                                }
                            },
                            if copied() { "Copied" } else { "Copy words" }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "onboarding-download-recovery-key",
                            onclick: {
                                let key = recovery_key();
                                let handoff_handle = handoff.account_handle.clone();
                                move |_| {
                                    let handles = [handoff_handle.clone(), account_primary_handle()];
                                    let filename = crate::components::mls_backup_prompt::recovery_key_filename_from_handles(
                                        &handles,
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

                    div { class: "callout warn onboarding-recovery-warning",
                        div { class: "body",
                            strong { "Keep this offline." }
                            " Anyone with these words can recover the identity. Inkson cannot replace them for you."
                        }
                    }
                }

                div { class: "workflow-form onboarding-confirmation",
                    Label { html_for: "onboarding-recovery-key-confirm",
                        if resumes_reserved_identity { "Existing 24 words" } else { "Re-enter the 24 words" }
                    }
                    Textarea {
                        id: "onboarding-recovery-key-confirm",
                        "data-testid": "onboarding-recovery-key-confirm",
                        rows: "3",
                        autocomplete: "off",
                        value: "{confirmation}",
                        disabled: busy(),
                        placeholder: "Type or paste the words you saved",
                        oninput: move |event: FormEvent| confirmation.set(event.value()),
                    }
                }

                if !status().is_empty() {
                    div {
                        class: if busy() { "muted" } else { "form-hint-warn" },
                        role: "status",
                        "aria-live": "polite",
                        "data-testid": "account-handoff-status",
                        "{status}"
                    }
                }

                div { class: "onboarding-footer-actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        disabled: busy(),
                        onclick: move |_| {
                            choice.set(IdentityChoice::Choose);
                            status.set(String::new());
                        },
                        "Back"
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "onboarding-bind-identity",
                        disabled: busy() || confirmation().trim().is_empty(),
                        onclick: move |_| {
                            if !resumes_reserved_identity {
                                match recovery_key_confirmation_diff(&recovery_key(), &confirmation()) {
                                    RecoveryKeyConfirmationDiff::Match => {}
                                    RecoveryKeyConfirmationDiff::WordCount { entered } => {
                                        status.set(format!(
                                            "Enter all 24 words. You entered {entered}."
                                        ));
                                        return;
                                    }
                                    RecoveryKeyConfirmationDiff::MismatchAt { index } => {
                                        status.set(format!(
                                            "Word {index} does not match. Check your saved copy."
                                        ));
                                        return;
                                    }
                                }
                            }

                            let handoff = handoff_for_creation.clone();
                            let supplied_key = if resumes_reserved_identity {
                                confirmation()
                            } else {
                                recovery_key()
                            };
                            let device = handoff.device_id.clone();
                            let session = completion_session.clone();
                            busy.set(true);
                            status.set("Finishing setup…".to_owned());
                            controller.finish_setup(
                                handoff,
                                supplied_key,
                                device,
                                session,
                                resumes_reserved_identity,
                            );
                        },
                        if busy() { "Finishing…" } else if resumes_reserved_identity { "Continue setup" } else { "Save and continue" }
                    }
                    if handoff.reserved_identity.is_some() {
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "issue-identity-abandonment-challenge",
                            disabled: busy(),
                            onclick: move |_| {
                                let handoff = handoff_for_abandonment.clone();
                                busy.set(true);
                                status.set("Issuing explicit abandonment challenge…".to_owned());
                                controller.issue_abandonment_challenge(handoff);
                            },
                            "Give up this provisional identity"
                        }
                    }
                }
            }
        }
    }
}

/// What discarding a draft costs, which depends entirely on whether its account
/// binding was already registered. Before the binding, the draft is local and
/// worthless; after it, this device holds the only copy of the material that
/// finishes an identity the account is already committed to.
fn discard_consequence(binding_registered: bool) -> &'static str {
    if binding_registered {
        "This identity is already registered to your account. Sign in to resume it or use the authenticated abandonment flow; deleting only this browser's checkpoint would not abandon the server reservation."
    } else {
        "Nothing has been registered yet. Discarding starts over: sign in again, and this device creates a new identity with a new Recovery Key."
    }
}

/// The way out of an unfinished server reservation this device cannot finish.
///
/// Onboarding is otherwise a one-way surface: without this, a draft that the
/// server no longer honours (or whose 24 words are gone) leaves clearing the
/// browser's site data as the only escape.
#[component]
fn DiscardSavedSetup(disabled: bool, on_discard: EventHandler<()>) -> Element {
    let state_store = crate::app::SessionContext::get().state_store;
    let mut busy = use_signal(|| false);
    let mut status = use_signal(String::new);
    let controller = DiscardSetupController {
        busy,
        status,
        state_store,
    };

    rsx! {
        div { class: "onboarding-discard",
            Button {
                variant: ButtonVariant::Secondary,
                "data-testid": "onboarding-discard-saved-setup",
                disabled: disabled || busy(),
                onclick: move |_| {
                    busy.set(true);
                    status.set(String::new());
                    controller.discard(on_discard);
                },
                if busy() { "Discarding…" } else { "Discard unfinished setup" }
            }
            if !status().is_empty() {
                div {
                    class: "form-hint-warn",
                    role: "alert",
                    "data-testid": "onboarding-discard-status",
                    "{status}"
                }
            }
        }
    }
}

#[component]
fn StalePrincipalSetup(on_discard: EventHandler<()>) -> Element {
    let state_store = crate::app::SessionContext::get().state_store;
    // Read the draft once, without subscribing: the discard this surface offers
    // clears the very checkpoint being described, and a subscribed read would
    // repaint it as an empty node before the parent re-routes.
    let (did_label, binding_registered) = use_hook(move || {
        state_store
            .peek()
            .pending_principal_registration()
            .map(|checkpoint| {
                (
                    short_protocol_id(checkpoint.did.as_str()),
                    checkpoint.stage
                        != crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
                )
            })
            .unwrap_or_else(|| ("an earlier identity".to_owned(), false))
    });

    rsx! {
        div { class: "event onboarding-card", "data-testid": "stale-principal-setup",
            SetupProgress { current: 2 }
            div { class: "onboarding-heading",
                span { class: "eyebrow", "Continue setup" }
                h2 { "This unfinished setup can't be finished here" }
                p { class: "muted",
                    "An unfinished identity setup for {did_label} is stored on this device, but this browser no longer holds the account session it needs to continue."
                }
            }

            div { class: "callout warn",
                div { class: "body",
                    strong { "Sign in to continue it." }
                    " Signing in to the same account restores what this setup needs. "
                    "{discard_consequence(binding_registered)}"
                }
            }

            div { class: "onboarding-footer-actions",
                if !binding_registered {
                    DiscardSavedSetup { disabled: false, on_discard }
                }
                Link { class: "primary", to: Route::Login, "Sign in" }
            }
        }
    }
}

#[component]
fn RecoveryKeyWords(recovery_key: String) -> Element {
    let words: Vec<String> = recovery_key
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect();
    rsx! {
        div { class: "recovery-key-hero onboarding-recovery-key",
            ol { class: "recovery-key-grid", "data-testid": "onboarding-recovery-key-display",
                for word in words {
                    li { class: "rk-word", "{word}", " " }
                }
            }
        }
    }
}
