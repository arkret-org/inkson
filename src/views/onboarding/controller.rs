//! The onboarding panel's writes, out of the `rsx!` and named.
//!
//! Nine `{ let Some(scope)=owner.upgrade()else{return;};let _=scope.owner().spawn(async move { …
//! }); }` blocks used to sit inside `onclick` attributes, one of them a hundred lines deep in the
//! nesting. They read and wrote the panel's Signals directly, so the only way to reach any of them
//! was to mount the component that held them.
//!
//! Each controller below is the bundle of Signals one screen's writes land in,
//! and every write is one named method on it. The `rsx!` keeps the synchronous
//! half of each click: read the durable handoff, refuse the action when it is
//! missing, set the busy flag and the in-progress status line.

type Navigator = Rc<InksonContext>;

use super::*;

/// Signals the device-pairing writes fold their outcome back into.
#[derive(Clone)]
pub(super) struct DevicePairingController {
    pub(super) context: Rc<InksonContext>,
    pub(super) owner: glory::ui::WeakScope,
    pub(super) busy: Cage<bool>,
    pub(super) status: Cage<String>,
    pub(super) request: Cage<Option<DeviceSetupPairingRequest>>,
}

impl DevicePairingController {
    /// Mint a fresh pairing handoff token and deep link for this device.
    pub(super) fn start(self, handoff: crate::state::PendingAccountHandoff) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            context: _,
            owner: _,
            busy,
            status,
            request,
        } = self;
        {
            let Some(scope) = owner.upgrade() else {
                return;
            };
            let _=scope.owner().spawn(async move {
            match stage_device_setup_pairing(&handoff).await {
                Ok(staged) => {
                    request.revise(|value|{let next=Some(staged);*value=next;});
                    status.revise(|value|{let next="Pairing QR code created. Nothing was sent automatically: scan or open it on an authorized device, then compare the code before approving."
                            .to_owned();*value=next;});
                }
                Err(error) => {
                    status.revise(|value|{let next=format!("Could not generate the device pairing QR: {error}");*value=next;})
                }
            }
            busy.revise(|value|{let next=false;*value=next;});
        });
        };
    }

    /// Poll the authorized pairing status for the handoff already staged.
    pub(super) fn check(
        self,
        handoff: crate::state::PendingAccountHandoff,
        staged: DeviceSetupPairingRequest,
    ) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            context: _,
            owner: _,
            busy,
            status,
            request,
        } = self;
        {
            let Some(scope) = owner.upgrade() else {
                return;
            };
            let _=scope.owner().spawn(async move {
            match check_device_setup_pairing(&handoff, &staged).await {
                Ok(arkret_sdk::DevicePairingState::Authorized) => {
                    status.revise(|value|{let next="Device authorization is accepted. Sign in again to verify the accepted authorization Event before this device is installed."
                            .to_owned();*value=next;});
                }
                Ok(arkret_sdk::DevicePairingState::ReadyForClaim) => {
                    status.revise(|value|{let next="Still waiting. Scan the QR, open the link, or type the code on an authorized device; this flow does not send an automatic prompt."
                            .to_owned();*value=next;});
                }
                Ok(arkret_sdk::DevicePairingState::Staged) => {
                    // The record exists but carries no target proof yet, so no
                    // sibling can claim it. Showing "waiting for approval" here
                    // would send the user to look at a request that is not
                    // reachable from any of the three entry points.
                    request.revise(|value|{let next=None;*value=next;});
                    status.revise(|value|{let next="This pairing request was never completed on this device. Generate a new pairing QR."
                            .to_owned();*value=next;});
                }
                Ok(arkret_sdk::DevicePairingState::Expired) => {
                    request.revise(|value|{let next=None;*value=next;});
                    status
                        .revise(|value|{let next="This pairing request expired. Generate a new pairing QR.".to_owned();*value=next;});
                }
                Err(error) => status.revise(|value|{let next=format!(
                    "Device authorization could not be verified: {error}"
                );*value=next;}),
            }
            busy.revise(|value|{let next=false;*value=next;});
        });
        };
    }
}

/// Signals the PCR-policy device recovery folds its outcome back into.
#[derive(Clone)]
pub(super) struct PcrRecoveryController {
    pub(super) context: Rc<InksonContext>,
    pub(super) owner: glory::ui::WeakScope,
    pub(super) busy: Cage<bool>,
    pub(super) status: Cage<String>,
    pub(super) words: Cage<String>,
    pub(super) state_store: crate::presentation::SharedStateStore,
    pub(super) token: Cage<String>,
    pub(super) principal_id: Cage<Option<arkret_sdk::DidCoreId>>,
    pub(super) device_id: Cage<String>,
    pub(super) config_store: Cage<crate::config::LocalConfigStore>,
    pub(super) active_account: Cage<Option<crate::config::ActiveAccountContext>>,
    pub(super) session_generation: Cage<u64>,
    pub(super) needs_device_authorization: Cage<bool>,
    pub(super) device_authorization_check_complete: Cage<bool>,
}

/// Signals the identity-creation and abandonment writes fold their outcome
/// back into.
#[derive(Clone)]
pub(super) struct IdentityCreationController {
    pub(super) context: Rc<InksonContext>,
    pub(super) owner: glory::ui::WeakScope,
    pub(super) busy: Cage<bool>,
    pub(super) status: Cage<String>,
    pub(super) recovery_key: Cage<String>,
    pub(super) recovery_key_state: Cage<arkret_sdk::IdentityCreationRecoveryKeyState>,
    pub(super) confirmation: Cage<String>,
    pub(super) complete: Cage<bool>,
    pub(super) resume_terminal: Cage<Option<ResumeTerminal>>,
    pub(super) state_store: crate::presentation::SharedStateStore,
    pub(super) config_store: Cage<crate::config::LocalConfigStore>,
    pub(super) active_account: Cage<Option<crate::config::ActiveAccountContext>>,
    pub(super) token: Cage<String>,
    pub(super) session_generation: Cage<u64>,
    pub(super) principal_id: Cage<Option<arkret_sdk::DidCoreId>>,
    pub(super) device_id: Cage<String>,
    pub(super) needs_device_authorization: Cage<bool>,
    pub(super) device_authorization_check_complete: Cage<bool>,
}

impl PcrRecoveryController {
    /// Recover this device against a bound principal using the Recovery Key,
    /// then commit the account the recovery produced.
    pub(super) fn recover_device(
        self,
        handoff: crate::state::PendingAccountHandoff,
        principal_did: arkret_sdk::Did,
        recovery_words: String,
        replacement_device_id: String,
        session: crate::runtime::session::SessionCoordinator,
        navigator: Navigator,
    ) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            context: _,
            owner: _,
            busy,
            status,
            words,
            state_store,
            token,
            principal_id,
            device_id,
            config_store,
            active_account,
            session_generation,
            needs_device_authorization,
            device_authorization_check_complete,
        } = self;
        {
            let Some(scope) = owner.upgrade() else {
                return;
            };
            let _=scope.owner().spawn(async move {
            let recovery_words = zeroize::Zeroizing::new(recovery_words);
            let result = recover_bound_principal_device(
                &handoff,
                &principal_did,
                &replacement_device_id,
                &recovery_words,
                state_store.clone(),
            )
            .await;
            words.revise(|value|{let next=String::new();*value=next;});
            match result {
                Ok((recovery, completed)) => {
                    match commit_completed_account(
                        &completed,
                        &recovery_words,
                        state_store.clone(),
                        config_store,
                        active_account,
                        token,
                        &session,
                        session_generation,
                        principal_id,
                        device_id,
                        needs_device_authorization,
                        device_authorization_check_complete,
                        Some(&recovery.pending),
                    )
                    .await
                    {
                        Ok(()) => match clear_pending_principal_setup(state_store.clone()).await {
                            Ok(()) => {
                                status.revise(|value|{let next=format!(
                                    "Identity recovered. Device receipt {} and the Standard session grant are durable.",
                                    recovery.readiness.terminal_receipt_id
                                );*value=next;});
                                navigator.navigate(Route::Dashboard);
                            }
                            Err(error) => status.revise(|value|{let next=format!(
                                "Identity recovered, but local cleanup failed: {error:#}"
                            );*value=next;}),
                        },
                        Err(error) => status.revise(|value|{let next=format!(
                            "Recovered device could not be committed: {error:#}"
                        );*value=next;}),
                    }
                }
                Err(error) => status.revise(|value|{let next=format!("Recovery could not finish: {error:#}");*value=next;}),
            }
            busy.revise(|value|{let next=false;*value=next;});
        });
        };
    }
}

impl IdentityCreationController {
    /// Clear a setup this device can no longer finish and return to sign-in.
    pub(super) fn clear_stranded_setup(self, navigator: Navigator) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            context: _,
            owner: _,
            busy,
            status,
            state_store,
            ..
        } = self;
        {
            let Some(scope) = owner.upgrade() else {
                return;
            };
            let _ = scope.owner().spawn(async move {
                match clear_pending_principal_setup(state_store.clone()).await {
                    Ok(()) => {
                        navigator.navigate(Route::Login);
                    }
                    Err(error) => status.revise(|value| {
                        let next = format!("Could not clear this setup: {error:#}");
                        *value = next;
                    }),
                }
                busy.revise(|value| {
                    let next = false;
                    *value = next;
                });
            });
        };
    }

    /// Confirm explicit abandonment of the reserved identity.
    pub(super) fn confirm_abandonment(
        self,
        handoff: crate::state::PendingAccountHandoff,
        pending: crate::state::PendingIdentityAbandonment,
        navigator: Navigator,
    ) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            context: _,
            owner: _,
            busy,
            status,
            state_store,
            ..
        } = self;
        {
            let Some(scope) = owner.upgrade() else {
                return;
            };
            let _=scope.owner().spawn(async move {
            let result = async {
                let dpop = state_store.write(|store| -> anyhow::Result<_> {Ok({

                    crate::identity::account_auth::grant_dpop::ensure_device_key(store)?
                })})?;
                crate::identity::identity_abandonment::confirm(&handoff, &pending, &dpop).await?;
                clear_pending_principal_setup(state_store.clone()).await
            }
            .await;
            match result {
                Ok(()) => {
                    status.revise(|value|{let next="Provisional identity abandoned. Authenticate to create a new identity root.".to_owned();*value=next;});
                    navigator.navigate(Route::Login);
                }
                Err(error) => status.revise(|value|{let next=format!("Identity abandonment failed: {error}");*value=next;}),
            }
            busy.revise(|value|{let next=false;*value=next;});
        });
        };
    }

    /// Freeze the explicit abandonment command for user review.
    pub(super) fn prepare_abandonment(self, mut handoff: crate::state::PendingAccountHandoff) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            context: _,
            owner: _,
            busy,
            status,
            state_store,
            ..
        } = self;
        {
            let Some(scope) = owner.upgrade() else {
                return;
            };
            let _=scope.owner().spawn(async move {
            let result = async {
                let pending = crate::identity::identity_abandonment::prepare(&handoff)?;
                handoff.identity_abandonment = Some(pending);
                let barrier = state_store.write(|store| -> anyhow::Result<_> {Ok({

                    store.set_pending_account_handoff(Some(handoff.clone()))?;
                    store.begin_durable_flush()?
                })})?;
                barrier.wait().await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;
            match result {
                Ok(()) => status.revise(|value|{let next="Review the identity and authenticate again before confirming abandonment."
                        .to_owned();*value=next;}),
                Err(error) => status.revise(|value|{let next=format!("Could not prepare abandonment: {error}");*value=next;}),
            }
            busy.revise(|value|{let next=false;*value=next;});
        });
        };
    }

    /// Persist the Recovery Key, create and bind the identity, then commit the
    /// account it produced.
    pub(super) fn finish_setup(
        self,
        handoff: crate::state::PendingAccountHandoff,
        supplied_key: String,
        device: String,
        session: crate::runtime::session::SessionCoordinator,
        resumes_reserved_identity: bool,
    ) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            context: _,
            owner: _,
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
        } = self;
        {
            let Some(scope) = owner.upgrade() else {
                return;
            };
            let _=scope.owner().spawn(async move {
            let result = async {
                if resumes_reserved_identity {
                    crate::identity::principal_registration::validate_reserved_identity_recovery_key(
                        &handoff,
                        &supplied_key,
                    )?;
                }
                crate::identity::account_auth::persist_pending_identity_creation_recovery_key(
                    &handoff,
                    &supplied_key,
                )
                .await?;
                let confirmed_state = if resumes_reserved_identity {
                    arkret_sdk::IdentityCreationRecoveryKeyState::ExistingValidatedDurable
                } else {
                    arkret_sdk::IdentityCreationRecoveryKeyState::GeneratedLocallyValidatedDurable
                };
                recovery_key_state.revise(|value|{let next=confirmed_state;*value=next;});
                if !confirmed_state.can_control_identity() {
                    anyhow::bail!("Recovery Key is not ready for identity creation");
                }
                create_and_bind_identity(
                    &handoff,
                    &supplied_key,
                    &device,
                    state_store.clone(),
                    status,
                )
                .await
            }
            .await;

            match result {
                Ok(IdentityCreationCommandOutcome::Completed(completed)) => {
                    if let Err(error) = commit_completed_account(
                        &completed,
                        &supplied_key,
                        state_store.clone(),
                        config_store,
                        active_account,
                        token,
                        &session,
                        session_generation,
                        principal_id,
                        device_id,
                        needs_device_authorization,
                        device_authorization_check_complete,
                        None,
                    )
                    .await
                    {
                        status.revise(|value|{let next=format!(
                            "Account completion could not be committed: {error:#}"
                        );*value=next;});
                        busy.revise(|value|{let next=false;*value=next;});
                        return;
                    }
                    recovery_key.revise(|value|{let next=String::new();*value=next;});
                    recovery_key_state
                        .revise(|value|{let next=arkret_sdk::IdentityCreationRecoveryKeyState::Unavailable;*value=next;});
                    confirmation.revise(|value|{let next=String::new();*value=next;});
                    status.revise(|value|{let next=String::new();*value=next;});
                    complete.revise(|value|{let next=true;*value=next;});
                    if let Err(error) = clear_pending_principal_setup(state_store.clone()).await {
                        status.revise(|value|{let next=format!(
                            "Setup finished, but local cleanup failed: {error:#}"
                        );*value=next;});
                    }
                }
                Ok(IdentityCreationCommandOutcome::Terminal(terminal)) => {
                    status.revise(|value|{let next=String::new();*value=next;});
                    resume_terminal.revise(|value|{let next=Some(terminal);*value=next;});
                }
                Err(error) => {
                    let command_error = format!("{error:#}");
                    let correlation =
                        crate::identity::account_auth::transition::LoginCorrelation::for_handoff(
                            &handoff,
                        );
                    crate::identity::account_auth::transition::record_onboarding_completion_transition(
                        crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeRestore,
                        crate::identity::account_auth::transition::OnboardingCompletionOutcome::Failed,
                        "onboarding_continuation_failed",
                        &correlation,
                        None,
                    );
                    resume_terminal.revise(|value|{let next=Some(ResumeTerminal {
                        kind: ResumeTerminalKind::RetryableFailure,
                        reason: command_error,
                        inventory: Vec::new(),
                    });*value=next;});
                    status.revise(|value|{let next=String::new();*value=next;});
                }
            }
            busy.revise(|value|{let next=false;*value=next;});
        });
        };
    }
}

/// Signals the discard control folds its outcome back into.
#[derive(Clone)]
pub(super) struct DiscardSetupController {
    pub(super) context: Rc<InksonContext>,
    pub(super) owner: glory::ui::WeakScope,
    pub(super) busy: Cage<bool>,
    pub(super) status: Cage<String>,
    pub(super) state_store: crate::presentation::SharedStateStore,
}

impl DiscardSetupController {
    /// Drop the unfinished setup this device holds.
    pub(super) fn discard(self, on_discard: Rc<dyn Fn(())>) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            context: _,
            owner: _,
            busy,
            status,
            state_store,
        } = self;
        {
            let Some(scope) = owner.upgrade() else {
                return;
            };
            let _ = scope.owner().spawn(async move {
                match clear_pending_principal_setup(state_store.clone()).await {
                    // Deliberately stays busy on success: the parent
                    // re-routes and this control is unmounted.
                    Ok(()) => on_discard(()),
                    Err(error) => {
                        status.revise(|value| {
                            let next = format!("Could not discard the unfinished setup: {error}");
                            *value = next;
                        });
                        busy.revise(|value| {
                            let next = false;
                            *value = next;
                        });
                    }
                }
            });
        };
    }
}
