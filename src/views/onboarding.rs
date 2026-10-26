use std::rc::Rc;

use glory::{Cage, Scope};

use crate::presentation::{InksonContext, View};
use crate::recovery_crypto::{RecoveryKeyConfirmationDiff, recovery_key_confirmation_diff};
use crate::routes::Route;
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;
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

fn discard_consequence(binding_registered: bool) -> &'static str {
    if binding_registered {
        "This identity is already registered to your account. Sign in to resume it or use the authenticated abandonment flow; deleting only this browser's checkpoint would not abandon the server reservation."
    } else {
        "Nothing has been registered yet. Discarding starts over: sign in again, and this device creates a new identity with a new Recovery Key."
    }
}

fn button(
    key: &str,
    label: impl Into<glory::Lotus<String>>,
    class: &str,
    enabled: impl Into<glory::Lotus<bool>>,
    handler: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(format!("btn {class} {key}"))
            .label(label)
            .enabled(enabled)
            .on_press(handler),
    )
}
fn entry(
    key: &str,
    label: &str,
    value: Cage<String>,
    enabled: impl Into<glory::Lotus<bool>>,
) -> View {
    let enabled = enabled.into();
    Box::new(
        sapid::field(key)
            .unstyled()
            .class(format!("form-field {key}"))
            .label(label.to_owned())
            .control(move |field| {
                sapid::text_field()
                    .unstyled()
                    .class("textarea")
                    .field(field)
                    .multiline(true)
                    .value(value)
                    .enabled(enabled.clone())
                    .on_value_change(move |next| value.revise(|v| *v = next))
            }),
    )
}
fn link(context: Rc<InksonContext>, key: &str, label: &str, route: Route) -> View {
    button(key, label, "primary", true, move || {
        context.navigate(route.clone())
    })
}
fn progress(current: usize) -> View {
    stack(
        "onboarding-progress",
        ["Identity", "Recovery Key", "Ready"]
            .into_iter()
            .enumerate()
            .map(|(index, label)| {
                line(
                    if index + 1 == current {
                        "is-current"
                    } else if index + 1 < current {
                        "is-complete"
                    } else {
                        ""
                    },
                    vec![
                        paragraph(
                            "onboarding-progress-index",
                            if index + 1 < current {
                                "✓".to_owned()
                            } else {
                                (index + 1).to_string()
                            },
                        ),
                        plain(label),
                    ],
                )
            })
            .collect(),
    )
}
fn notice(title: &str, body: impl Into<glory::Lotus<String>>, children: Vec<View>) -> View {
    let mut nodes = vec![heading(2, "", title.to_owned()), paragraph("muted", body)];
    nodes.extend(children);
    stack("event onboarding-card onboarding-centered", nodes)
}
pub fn page(_scope: &Scope, context: Rc<InksonContext>, _route: Route) -> View {
    let ctx = context.clone();
    let ready = crate::presentation::widgets::reactive_distinct(
        context.secure_store_bootstrap_ready,
        move |scope, ready| {
            if !ready {
                return notice(
                    "Restoring identity setup",
                    "Reading this account's current server state…",
                    vec![],
                );
            }
            let ctx = ctx.clone();
            let resource = {
                let ctx = ctx.clone();
                crate::presentation::widgets::resource(scope, move || {
                    let _ = ctx.session_generation.get();
                    let store = ctx.state_store.clone();
                    let pending = store.read(|store| store.pending_account_handoff());
                    async move {
                        if pending.is_some_and(|handoff| {
                            handoff.retry_after_ms.is_none()
                                && (handoff.lease_id.is_some()
                                    || handoff.bound_principal_id.is_some())
                        }) {
                            crate::identity::account_auth::refresh_pending_onboarding(
                                &store.handle(),
                            )
                            .await
                            .map_err(|error| format!("{error:#}"))?;
                        }
                        Ok(())
                    }
                })
            };
            reactive(resource.data, move |scope, result| match result {
                None => notice(
                    "Checking identity setup",
                    "Loading the current Account Authority state…",
                    vec![],
                ),
                Some(Err(error)) => notice(
                    "Identity setup could not be refreshed",
                    "No local checkpoint was used to guess a next step.",
                    vec![
                        paragraph("error", error),
                        link(
                            ctx.clone(),
                            "onboarding-authenticate",
                            "Authenticate again",
                            Route::Login,
                        ),
                    ],
                ),
                Some(Ok(())) => flow(scope, ctx.clone()),
            })
        },
    );
    stack("timeline onboarding-flow onboarding-panel", vec![ready])
}
fn flow(scope: &Scope, context: Rc<InksonContext>) -> View {
    let reroute = scope.cage(0_u32);
    reactive(reroute, move |scope, _| {
        let surface = context.state_store.read(|store| {
            onboarding_surface(
                store.pending_account_handoff().as_ref(),
                store.pending_principal_registration().as_ref(),
            )
        });
        match surface {
            OnboardingSurface::DeviceSetupRequired => device_setup(scope, context.clone()),
            OnboardingSurface::IdentityCreation => identity_creation(scope, context.clone()),
            OnboardingSurface::StaleCheckpoint => stale_setup(
                scope,
                context.clone(),
                Rc::new(move |_| reroute.revise(|v| *v += 1)),
            ),
            OnboardingSurface::ServerStateConflict => notice(
                "Identity setup state could not be verified",
                "The Account Authority returned an inconsistent setup checkpoint. Local data was not used to guess the next step.",
                vec![link(
                    context.clone(),
                    "onboarding-authenticate",
                    "Authenticate again",
                    Route::Login,
                )],
            ),
            OnboardingSurface::AccountSummary => {
                let did = crate::app::principal_id_owned(context.principal_id.get_untracked());
                if account_summary_complete(!context.token.get_untracked().is_empty(), &did) {
                    notice(
                        "You're all set",
                        format!("Your account is linked to {}.", short_protocol_id(&did)),
                        vec![
                            paragraph("onboarding-finish-mark", "✓"),
                            link(
                                context.clone(),
                                "onboarding-continue",
                                "Continue",
                                Route::Dashboard,
                            ),
                        ],
                    )
                } else {
                    notice(
                        "Set up your identity",
                        "Sign in first, then choose whether to create or link an identity.",
                        vec![
                            paragraph("onboarding-finish-mark", "1"),
                            link(
                                context.clone(),
                                "onboarding-signin",
                                "Sign in",
                                Route::Login,
                            ),
                        ],
                    )
                }
            }
        }
    })
}
fn device_setup(scope: &Scope, context: Rc<InksonContext>) -> View {
    let selected = scope.cage(false);
    let busy = scope.cage(false);
    let status = scope.cage(String::new());
    let request = scope.cage(None::<DeviceSetupPairingRequest>);
    let controller = DevicePairingController {
        context: context.clone(),
        owner: scope.downgrade(),
        busy,
        status,
        request,
    };
    let ctx = context.clone();
    reactive(selected, move |scope, recovery| {
        if recovery {
            return device_recovery(scope, ctx.clone());
        }
        let bound = ctx.state_store.read(|store| {
            store
                .pending_account_handoff()
                .is_some_and(|handoff| handoff.bound_principal_id.is_some())
        });
        let enabled = scope.bond(move || !busy.get());
        let start = {
            let ctx = ctx.clone();
            let controller = controller.clone();
            button(
                "device-setup-pairing-start",
                scope.bond(move || {
                    if busy.get() {
                        "Preparing…"
                    } else {
                        "Generate pairing QR"
                    }
                    .to_owned()
                }),
                "primary",
                scope.bond(move || bound && !busy.get()),
                move || {
                    let Some(handoff) = ctx
                        .state_store
                        .read(|store| store.pending_account_handoff())
                    else {
                        status.revise(|v| {
                            *v = "The authenticated account handoff is missing. Sign in again."
                                .into()
                        });
                        return;
                    };
                    busy.revise(|v| *v = true);
                    status.revise(|v| *v = "Generating a device pairing QR code…".into());
                    controller.clone().start(handoff);
                },
            )
        };
        let details = {
            let ctx = ctx.clone();
            let controller = controller.clone();
            reactive(request, move |scope, staged| {
                let Some(staged) = staged else {
                    return empty();
                };
                let qr = qrcode::QrCode::with_error_correction_level(
                    staged.deep_link.as_bytes(),
                    qrcode::EcLevel::M,
                )
                .map(|code| {
                    code.render::<qrcode::render::svg::Color<'_>>()
                        .min_dimensions(192, 192)
                        .quiet_zone(true)
                        .build()
                })
                .unwrap_or_default();
                let owner = controller.clone();
                let ctx_poll = ctx.clone();
                stack(
                    "device-setup-pairing",
                    vec![
                        line(
                            "device-pair-approval-code-block",
                            vec![
                                paragraph("muted", "Compare this code before approving"),
                                paragraph(
                                    "device-pair-approval-code mono device-setup-pairing-code",
                                    staged.pairing_code.to_string(),
                                ),
                            ],
                        ),
                        crate::components::qr_share_panel(
                            scope,
                            ctx.clone(),
                            crate::components::QrSharePanelProps {
                                qr_svg: qr,
                                url: staged.deep_link,
                                qr_aria_label: "Device pairing QR code".into(),
                                url_aria_label: "Device pairing link".into(),
                                qr_test_id: "device-setup-pairing-qr".into(),
                                url_test_id: "device-setup-pairing-link".into(),
                                copy_test_id: "device-setup-pairing-copy".into(),
                                url_rows: 4,
                            },
                        ),
                        button(
                            "device-setup-pairing-status",
                            "Check authorization status",
                            "secondary",
                            enabled,
                            move || {
                                let Some(handoff) = ctx_poll
                                    .state_store
                                    .read(|store| store.pending_account_handoff())
                                else {
                                    status.revise(|v|*v="The authenticated account handoff is missing. Sign in again.".into());
                                    return;
                                };
                                let Some(staged) = request.get_untracked() else {
                                    status.revise(|v| *v = "Generate a pairing QR first.".into());
                                    return;
                                };
                                busy.revise(|v| *v = true);
                                status.revise(|v| *v = "Checking device authorization…".into());
                                owner.clone().check(handoff, staged);
                            },
                        ),
                    ],
                )
            })
        };
        let recover = {
            let ctx = ctx.clone();
            button(
                "device-setup-use-recovery-key",
                "Use Recovery Key instead",
                "ghost",
                true,
                move || {
                    let handoff = ctx
                        .state_store
                        .read(|store| store.pending_account_handoff());
                    let(correlation,bound,no_returning_device)=handoff.as_ref().map_or_else(||(crate::identity::account_auth::transition::LoginCorrelation::default(),false,false),|handoff|(crate::identity::account_auth::transition::LoginCorrelation::for_handoff(handoff),handoff.bound_principal_id.is_some(),matches!(handoff.bound_device_entry_state.as_ref(),Some(crate::state::BoundDeviceEntryState::NoReturningDevice))));
                    if crate::identity::account_auth::transition::record_recovery_surface_opened(crate::identity::account_auth::transition::RecoveryEntryReason::UserSelectedInDeviceSetup,&correlation,bound,no_returning_device){selected.revise(|v|*v=true);}else{status.revise(|v|*v="This account's sign-in has no authoritative device decision yet, so Recovery Key entry stays closed. Sign in again and retry device approval.".into());}
                },
            )
        };
        stack(
            "event onboarding-card device-setup-required",
            vec![
                heading(2, "", "Authorize this device"),
                paragraph(
                    "muted",
                    "This account is already linked, but this browser has no currently accepted device key. Generate a pairing QR code or link, then scan or open it on an already-authorized device.",
                ),
                paragraph(
                    "muted",
                    "This server-mediated flow does not send a notification or open a prompt on your other devices. Login alone cannot authorize a new device, and no session was issued.",
                ),
                if bound {
                    start
                } else {
                    paragraph(
                        "error",
                        "The bound-account handoff is incomplete. No device flow was started.",
                    )
                },
                details,
                paragraph("muted device-setup-status", status),
                link(
                    ctx.clone(),
                    "device-setup-login",
                    "Sign in again after approval",
                    Route::Login,
                ),
                recover,
            ],
        )
    })
}
fn device_recovery(scope: &Scope, context: Rc<InksonContext>) -> View {
    let words = scope.cage(String::new());
    let status = scope.cage(String::new());
    let busy = scope.cage(false);
    let controller = PcrRecoveryController {
        context: context.clone(),
        owner: scope.downgrade(),
        busy,
        status,
        words,
        state_store: context.state_store.clone(),
        token: context.token,
        principal_id: context.principal_id,
        device_id: context.device_id,
        config_store: context.config_store,
        active_account: context.active_account,
        session_generation: context.session_generation,
        needs_device_authorization: context.needs_device_authorization,
        device_authorization_check_complete: context.device_authorization_check_complete,
    };
    let ctx = context.clone();
    let recover = button(
        "onboarding-recover-device",
        scope.bond(move || {
            if busy.get() {
                "Recovering…"
            } else {
                "Authorize this device"
            }
            .to_owned()
        }),
        "primary",
        scope.bond(move || !busy.get() && words.get().split_whitespace().count() == 24),
        move || {
            let Some(handoff) = ctx
                .state_store
                .read(|store| store.pending_account_handoff())
            else {
                status.revise(|v|*v="The authenticated account recovery checkpoint is missing. Sign in again.".into());
                return;
            };
            let Some(principal) = handoff.bound_principal_did.clone() else {
                status.revise(|v| {
                    *v = "This account does not require existing-identity recovery.".into()
                });
                return;
            };
            let device = handoff.device_id.clone();
            busy.revise(|v| *v = true);
            status.revise(|v| {
                *v = "Verifying Recovery Key and preparing a PCR-policy device recovery…".into()
            });
            controller.clone().recover_device(
                handoff,
                principal,
                words.get_untracked(),
                device,
                ctx.services.session.clone(),
                ctx.clone(),
            );
        },
    );
    stack(
        "event onboarding-card pcr-policy-device-recovery",
        vec![
            heading(2, "", "Recover this identity"),
            paragraph(
                "muted",
                "This account already has an identity. Enter its 24-word Recovery Key to satisfy the accepted recovery policy and authorize this device. No approval from another device or administrator is required.",
            ),
            entry(
                "root-recovery-words",
                "Recovery Key (24 words)",
                words,
                scope.bond(move || !busy.get()),
            ),
            recover,
            paragraph("muted", status),
        ],
    )
}

fn identity_creation(scope: &Scope, context: Rc<InksonContext>) -> View {
    let initial_handoff = context
        .state_store
        .read(|store| store.pending_account_handoff());
    let checkpoint = context
        .state_store
        .read(|store| store.pending_principal_registration());
    let retained = initial_handoff
        .as_ref()
        .and_then(|handoff| load_valid_retained_recovery_key(handoff, checkpoint.as_ref()));
    let source =
        RecoveryKeySource::for_initial_handoff(initial_handoff.as_ref(), retained.is_some());
    let source_requires = source.requires_existing_key();
    let source_retained = source.was_recovered_from_secure_store();
    let choice = scope.cage(initial_identity_choice(
        initial_handoff.as_ref(),
        retained.is_some(),
    ));
    let recovery_key_state = scope.cage(if retained.is_some() {
        arkret_sdk::IdentityCreationRecoveryKeyState::RecoveredPendingConfirmation
    } else {
        arkret_sdk::IdentityCreationRecoveryKeyState::Unavailable
    });
    let recovery_key = scope.cage(retained.unwrap_or_default());
    let confirmation = scope.cage(String::new());
    let copied = scope.cage(false);
    let busy = scope.cage(false);
    let complete = scope.cage(false);
    let status = scope.cage(String::new());
    let resume_terminal = scope.cage(None::<ResumeTerminal>);
    let controller = IdentityCreationController {
        context: context.clone(),
        owner: scope.downgrade(),
        busy,
        status,
        recovery_key,
        recovery_key_state,
        confirmation,
        complete,
        resume_terminal,
        state_store: context.state_store.clone(),
        config_store: context.config_store,
        active_account: context.active_account,
        token: context.token,
        session_generation: context.session_generation,
        principal_id: context.principal_id,
        device_id: context.device_id,
        needs_device_authorization: context.needs_device_authorization,
        device_authorization_check_complete: context.device_authorization_check_complete,
    };
    let state = {
        let ctx = context.clone();
        scope.bond(move || {
            let _ = ctx.state_revision.get();
            (complete.get(), resume_terminal.get(), choice.get())
        })
    };
    let ctx = context.clone();
    reactive(state, move |scope, (finished, terminal, selected)| {
        let enabled = scope.bond(move || !busy.get());
        if finished {
            return stack(
                "event onboarding-card account-handoff-onboarding",
                vec![
                    progress(3),
                    stack(
                        "onboarding-finished onboarding-complete",
                        vec![
                            paragraph("onboarding-finish-mark", "✓"),
                            heading(2, "", "Identity ready"),
                            paragraph(
                                "muted",
                                "Your account, this device, and recovery backup are ready.",
                            ),
                            paragraph("form-hint-warn", status),
                            link(
                                ctx.clone(),
                                "onboarding-continue",
                                "Continue",
                                Route::Dashboard,
                            ),
                        ],
                    ),
                ],
            );
        }
        if let Some(terminal) = terminal {
            let heading = match terminal.kind {
                ResumeTerminalKind::HydrationFailed => "Setup state could not be read",
                ResumeTerminalKind::RetryableFailure => "Setup continuation did not finish",
                ResumeTerminalKind::ReauthRequired => "Setup needs authentication",
                ResumeTerminalKind::StrandedIdentity => {
                    "This accepted identity cannot continue here"
                }
                ResumeTerminalKind::Contradiction => "Setup state is inconsistent",
            };
            let mut actions = vec![];
            if matches!(
                terminal.kind,
                ResumeTerminalKind::HydrationFailed | ResumeTerminalKind::RetryableFailure
            ) {
                actions.push(button(
                    "retry-onboarding-resume",
                    if terminal.kind == ResumeTerminalKind::HydrationFailed {
                        "Retry storage check"
                    } else {
                        "Retry exact continuation"
                    },
                    "primary",
                    true,
                    move || {
                        resume_terminal.revise(|v| *v = None);
                        status.revise(|v| v.clear());
                    },
                ));
            }
            if terminal.kind == ResumeTerminalKind::ReauthRequired {
                actions.push(link(
                    ctx.clone(),
                    "onboarding-signin",
                    "Sign in again",
                    Route::Login,
                ));
            }
            if matches!(
                terminal.kind,
                ResumeTerminalKind::StrandedIdentity | ResumeTerminalKind::Contradiction
            ) {
                actions.push(link(
                    ctx.clone(),
                    "onboarding-switch-account",
                    "Sign in another account",
                    Route::Login,
                ));
                let control = controller.clone();
                let nav = ctx.clone();
                actions.push(button(
                    "clear-stranded-onboarding",
                    if terminal.kind == ResumeTerminalKind::StrandedIdentity {
                        "Abandon this setup and register a new identity"
                    } else {
                        "Clear this setup"
                    },
                    "primary",
                    enabled,
                    move || {
                        busy.revise(|v| *v = true);
                        control.clone().clear_stranded_setup(nav.clone());
                    },
                ));
            }
            return notice(
                heading,
                terminal.reason,
                vec![
                    stack(
                        "muted onboarding-resume-inventory",
                        terminal.inventory.into_iter().map(plain).collect(),
                    ),
                    line("onboarding-footer-actions", actions),
                    paragraph("form-hint-warn", status),
                ],
            );
        }
        let handoff = ctx
            .state_store
            .read(|store| store.pending_account_handoff());
        let Some(handoff) = handoff else {
            let did = crate::app::principal_id_owned(ctx.principal_id.get_untracked());
            return match missing_creation_handoff_surface(
                busy.get_untracked(),
                !ctx.token.get_untracked().is_empty(),
                &did,
            ) {
                MissingCreationHandoffSurface::Finishing => notice(
                    "Finishing identity setup",
                    "The account binding was accepted. Inkson is finishing the local recovery and session records…",
                    vec![progress(3), paragraph("muted", status)],
                ),
                MissingCreationHandoffSurface::Complete => notice(
                    "Identity ready",
                    "Your account, this device, and recovery backup are ready.",
                    vec![
                        progress(3),
                        paragraph("onboarding-finish-mark", "✓"),
                        link(
                            ctx.clone(),
                            "onboarding-continue",
                            "Continue",
                            Route::Dashboard,
                        ),
                    ],
                ),
                MissingCreationHandoffSurface::SignInRequired => notice(
                    "Identity setup needs authentication",
                    "The previous account handoff is no longer available. Sign in again so Inkson can resume from the current Account Authority state.",
                    vec![
                        paragraph("form-hint-warn", status),
                        link(
                            ctx.clone(),
                            "onboarding-signin",
                            "Sign in again",
                            Route::Login,
                        ),
                    ],
                ),
            };
        };
        if let Some(delay) = handoff.retry_after_ms {
            return notice(
                "Setup is already in progress",
                format!(
                    "Continue in the open setup, or wait about {} seconds and then sign in again on this device.",
                    delay.div_ceil(1000).max(1)
                ),
                vec![link(
                    ctx.clone(),
                    "onboarding-signin",
                    "Sign in again",
                    Route::Login,
                )],
            );
        }
        if handoff.expires_at <= chrono::Utc::now()
            || handoff
                .lease_expires_at
                .is_some_and(|expiry| expiry <= chrono::Utc::now())
        {
            return notice(
                "Setup expired",
                "Sign in again so Inkson can recalculate the flow from the current server state. A matching Recovery Key retained in this device's secure store will be re-confirmed; otherwise Inkson will ask for the original key or offer explicit abandonment.",
                vec![link(
                    ctx.clone(),
                    "onboarding-signin",
                    "Sign in again",
                    Route::Login,
                )],
            );
        }
        let pending_abandonment = handoff.identity_abandonment.clone().or_else(|| {
            ctx.state_store.read(|store| {
                store
                    .pending_principal_registration()
                    .and_then(|checkpoint| checkpoint.identity_abandonment)
            })
        });
        let mut children = vec![progress(if selected == IdentityChoice::Create {
            2
        } else {
            1
        })];
        if let Some(pending) = pending_abandonment {
            children.push(stack("onboarding-heading",vec![paragraph("eyebrow","Explicit abandonment"),heading(2,"","Confirm giving up this provisional identity"),paragraph("muted","The orphan anchor will be permanently unusable and cannot be deactivated or continued. A new identity root DID and PCR must be created.")]));
            children.push(stack(
                "callout warn",
                vec![paragraph(
                    "body",
                    "This cannot be undone. Confirm only after re-authenticating the account.",
                )],
            ));
            let control = controller.clone();
            let nav = ctx.clone();
            children.push(line("onboarding-footer-actions",vec![link(ctx.clone(),"onboarding-authenticate","Authenticate again",Route::Login),button("confirm-identity-abandonment",scope.bond(move||if busy.get(){"Confirming…"}else{"Permanently abandon identity"}.to_owned()),"primary",enabled,move||{let Some(handoff)=nav.state_store.read(|store|store.pending_account_handoff())else{status.revise(|v|*v="Authenticate the account again before confirming abandonment.".into());return;};busy.revise(|v|*v=true);status.revise(|v|*v="Confirming explicit abandonment…".into());control.clone().confirm_abandonment(handoff,pending.clone(),nav.clone());})]));
            children.push(paragraph("form-hint-warn", status));
            return stack("event onboarding-card account-handoff-onboarding", children);
        }
        if selected == IdentityChoice::Choose {
            children.push(stack("onboarding-heading",vec![heading(2,"",if source_requires{"An identity reservation is unfinished"}else{"Set up your identity"}),paragraph("muted",if source_requires{"The server has an unfinished identity reservation. That does not mean Inkson knows you saved its Recovery Key. Enter the original key if you still have it, or explicitly abandon this reservation before creating another identity."}else{"Inkson creates one identity for this account and authorizes this device as its first device."})]));
            let hosting = hosting_label(&handoff.station_url);
            children.push(stack("identity-choice-grid",vec![stack("identity-choice-card is-recommended",vec![heading(3,"",if source_requires{"Verify the original Recovery Key"}else{"Create your identity"}),paragraph("",if source_requires{format!("The reserved identity is hosted with {hosting}. Inkson does not infer key possession from the reservation; it will verify the original key locally before continuing.")}else{format!("It will be anchored by a Recovery Key and hosted with {hosting}. No device approval step is needed.")}),if source_requires{empty()}else{paragraph("muted",format!("This deployment creates a {CURRENT_DEPLOYMENT_HUMAN_ANCHOR_METHOD} identity. Arkret also permits did:web and did:key human anchors in deployments that support them; they are not registration options here."))},button("choose-new-identity",if source_requires{"Enter existing key"}else{"Continue"},"primary",true,move||{choice.revise(|v|*v=IdentityChoice::Create);if !source_requires&&recovery_key.get_untracked().is_empty(){match crate::recovery_crypto::generate_recovery_key(){Ok(key)=>{recovery_key.revise(|v|*v=key);recovery_key_state.revise(|v|*v=arkret_sdk::IdentityCreationRecoveryKeyState::GeneratedPendingConfirmation);confirmation.revise(|v|v.clear());copied.revise(|v|*v=false);status.revise(|v|v.clear());},Err(error)=>status.revise(|v|*v=format!("Could not create a Recovery Key: {error}"))}}})]) ]));
            children.push(paragraph("form-hint-warn", status));
            return stack("event onboarding-card account-handoff-onboarding", children);
        }
        let title = if source_requires {
            "Enter your existing Recovery Key"
        } else if source_retained {
            "Re-confirm your Recovery Key"
        } else {
            "Save your Recovery Key"
        };
        let intro = if source_requires {
            "Inkson cannot replace the key that controls this reserved identity. If it is lost, use the explicit abandonment action below."
        } else if source_retained {
            "This device securely retained the same 24 words from the unfinished setup. Re-confirm them before continuing; their presence here does not mean Inkson assumes you memorized or backed them up."
        } else {
            "Write down these 24 words in order. They will not be shown again."
        };
        children.push(stack(
            "onboarding-heading",
            vec![heading(2, "", title), paragraph("muted", intro)],
        ));
        if !source_requires {
            children.push(reactive(recovery_key, move |_, key| {
                stack(
                    "recovery-key-hero onboarding-recovery-key",
                    vec![stack(
                        "recovery-key-grid onboarding-recovery-key-display",
                        key.split_whitespace()
                            .map(|word| paragraph("rk-word", word.to_owned()))
                            .collect(),
                    )],
                )
            }));
            let handoff_handle = handoff.account_handle.clone();
            let primary = ctx.account_primary_handle;
            children.push(line("onboarding-key-actions",vec![button("onboarding-copy-recovery-key",scope.bond(move||if copied.get(){"Copied"}else{"Copy words"}.to_owned()),"secondary",true,move||{crate::components::mls_backup_prompt::copy_text_to_clipboard(&recovery_key.get_untracked());copied.revise(|v|*v=true);}),button("onboarding-download-recovery-key","Download .txt","secondary",true,move||{let filename=crate::components::mls_backup_prompt::recovery_key_filename_from_handles(&[handoff_handle.clone(),primary.get_untracked()]);crate::components::mls_backup_prompt::download_text_as_file(&filename,&recovery_key.get_untracked());})]));
            children.push(stack("callout warn onboarding-recovery-warning",vec![paragraph("body","Keep this offline. Anyone with these words can recover the identity. Inkson cannot replace them for you.")]));
        }
        children.push(stack(
            "workflow-form onboarding-confirmation",
            vec![entry(
                "onboarding-recovery-key-confirm",
                if source_requires {
                    "Existing 24 words"
                } else {
                    "Re-enter the 24 words"
                },
                confirmation,
                enabled,
            )],
        ));
        children.push(paragraph("form-hint-warn account-handoff-status", status));
        let control = controller.clone();
        let completion_session = ctx.services.session.clone();
        let creation = handoff.clone();
        let mut actions = vec![
            button("onboarding-back", "Back", "secondary", enabled, move || {
                choice.revise(|v| *v = IdentityChoice::Choose);
                status.revise(|v| v.clear());
            }),
            button(
                "onboarding-bind-identity",
                scope.bond(move || {
                    if busy.get() {
                        "Finishing…"
                    } else if source_requires {
                        "Continue setup"
                    } else {
                        "Save and continue"
                    }
                    .to_owned()
                }),
                "primary",
                scope.bond(move || !busy.get() && !confirmation.get().trim().is_empty()),
                move || {
                    if !source_requires {
                        match recovery_key_confirmation_diff(
                            &recovery_key.get_untracked(),
                            &confirmation.get_untracked(),
                        ) {
                            RecoveryKeyConfirmationDiff::Match => {}
                            RecoveryKeyConfirmationDiff::WordCount { entered } => {
                                status.revise(|v| {
                                    *v = format!("Enter all 24 words. You entered {entered}.")
                                });
                                return;
                            }
                            RecoveryKeyConfirmationDiff::MismatchAt { index } => {
                                status.revise(|v| {
                                    *v = format!(
                                        "Word {index} does not match. Check your saved copy."
                                    )
                                });
                                return;
                            }
                        }
                    }
                    let supplied = if source_requires {
                        confirmation.get_untracked()
                    } else {
                        recovery_key.get_untracked()
                    };
                    let device = creation.device_id.clone();
                    busy.revise(|v| *v = true);
                    status.revise(|v| *v = "Finishing setup…".into());
                    control.clone().finish_setup(
                        creation.clone(),
                        supplied,
                        device,
                        completion_session.clone(),
                        source_requires,
                    );
                },
            ),
        ];
        if handoff.reserved_identity.is_some() {
            let control = controller.clone();
            actions.push(button(
                "prepare-identity-abandonment",
                "Give up this provisional identity",
                "secondary",
                enabled,
                move || {
                    busy.revise(|v| *v = true);
                    status.revise(|v| *v = "Preparing explicit abandonment…".into());
                    control.clone().prepare_abandonment(handoff.clone());
                },
            ));
        }
        children.push(line("onboarding-footer-actions", actions));
        stack("event onboarding-card account-handoff-onboarding", children)
    })
}
fn stale_setup(scope: &Scope, context: Rc<InksonContext>, on_discard: Rc<dyn Fn(())>) -> View {
    let (did, bound) = context.state_store.read(|store| {
        store
            .pending_principal_registration()
            .map(|checkpoint| {
                (
                    short_protocol_id(checkpoint.did.as_str()),
                    checkpoint.stage
                        != crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
                )
            })
            .unwrap_or_else(|| ("an earlier identity".into(), false))
    });
    let mut actions = vec![];
    if !bound {
        let busy = scope.cage(false);
        let status = scope.cage(String::new());
        let controller = DiscardSetupController {
            context: context.clone(),
            owner: scope.downgrade(),
            busy,
            status,
            state_store: context.state_store.clone(),
        };
        actions.push(stack(
            "onboarding-discard",
            vec![
                button(
                    "onboarding-discard-saved-setup",
                    scope.bond(move || {
                        if busy.get() {
                            "Discarding…"
                        } else {
                            "Discard unfinished setup"
                        }
                        .to_owned()
                    }),
                    "secondary",
                    scope.bond(move || !busy.get()),
                    move || {
                        busy.revise(|v| *v = true);
                        status.revise(|v| v.clear());
                        controller.clone().discard(on_discard.clone());
                    },
                ),
                paragraph("form-hint-warn onboarding-discard-status", status),
            ],
        ));
    }
    actions.push(link(
        context.clone(),
        "onboarding-signin",
        "Sign in",
        Route::Login,
    ));
    stack(
        "event onboarding-card stale-principal-setup",
        vec![
            progress(2),
            stack(
                "onboarding-heading",
                vec![
                    paragraph("eyebrow", "Continue setup"),
                    heading(2, "", "This unfinished setup can't be finished here"),
                    paragraph(
                        "muted",
                        format!(
                            "An unfinished identity setup for {did} is stored on this device, but this browser no longer holds the account session it needs to continue."
                        ),
                    ),
                ],
            ),
            stack(
                "callout warn",
                vec![paragraph(
                    "body",
                    format!(
                        "Sign in to continue it. Signing in to the same account restores what this setup needs. {}",
                        discard_consequence(bound)
                    ),
                )],
            ),
            line("onboarding-footer-actions", actions),
        ],
    )
}
