//! The onboarding panel's writes, out of the `rsx!` and named.
//!
//! Nine `spawn(async move { … })` blocks used to sit inside `onclick`
//! attributes, one of them a hundred lines deep in the nesting. They read and
//! wrote the panel's Signals directly, so the only way to reach any of them was
//! to mount the component that held them.
//!
//! Each controller below is the bundle of Signals one screen's writes land in,
//! and every write is one named method on it. The `rsx!` keeps the synchronous
//! half of each click: read the durable handoff, refuse the action when it is
//! missing, set the busy flag and the in-progress status line.

use dioxus_router::Navigator;

use super::*;

/// Signals the device-pairing writes fold their outcome back into.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct DevicePairingController {
    pub(super) busy: Signal<bool>,
    pub(super) status: Signal<String>,
    pub(super) request: Signal<Option<DeviceSetupPairingRequest>>,
}

impl DevicePairingController {
    /// Mint a fresh pairing handoff token and deep link for this device.
    pub(super) fn start(self, handoff: crate::state::PendingAccountHandoff) {
        let Self {
            mut busy,
            mut status,
            mut request,
        } = self;
        spawn(async move {
            match stage_device_setup_pairing(&handoff).await {
                Ok(staged) => {
                    request.set(Some(staged));
                    status.set(
                        "Pairing QR code created. Nothing was sent automatically: scan or open it on an authorized device, then compare the code before approving."
                            .to_owned(),
                    );
                }
                Err(error) => {
                    status.set(format!("Could not generate the device pairing QR: {error}"))
                }
            }
            busy.set(false);
        });
    }

    /// Poll the authorized pairing status for the handoff already staged.
    pub(super) fn check(
        self,
        handoff: crate::state::PendingAccountHandoff,
        staged: DeviceSetupPairingRequest,
    ) {
        let Self {
            mut busy,
            mut status,
            mut request,
        } = self;
        spawn(async move {
            match check_device_setup_pairing(&handoff, &staged).await {
                Ok(arkret_sdk::DevicePairingState::Authorized) => {
                    status.set(
                        "Device authorization is accepted. Sign in again to verify the accepted authorization Event before this device is installed."
                            .to_owned(),
                    );
                }
                Ok(arkret_sdk::DevicePairingState::ReadyForClaim) => {
                    status.set(
                        "Still waiting. Scan the QR, open the link, or type the code on an authorized device; this flow does not send an automatic prompt."
                            .to_owned(),
                    );
                }
                Ok(arkret_sdk::DevicePairingState::Staged) => {
                    // The record exists but carries no target proof yet, so no
                    // sibling can claim it. Showing "waiting for approval" here
                    // would send the user to look at a request that is not
                    // reachable from any of the three entry points.
                    request.set(None);
                    status.set(
                        "This pairing request was never completed on this device. Generate a new pairing QR."
                            .to_owned(),
                    );
                }
                Ok(arkret_sdk::DevicePairingState::Expired) => {
                    request.set(None);
                    status
                        .set("This pairing request expired. Generate a new pairing QR.".to_owned());
                }
                Err(error) => status.set(format!(
                    "Device authorization could not be verified: {error}"
                )),
            }
            busy.set(false);
        });
    }
}

/// Signals the PCR-policy device recovery folds its outcome back into.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct PcrRecoveryController {
    pub(super) busy: Signal<bool>,
    pub(super) status: Signal<String>,
    pub(super) words: Signal<String>,
    pub(super) state_store: SyncSignal<crate::state::LocalStateStore>,
    pub(super) token: Signal<String>,
    pub(super) principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub(super) device_id: Signal<String>,
    pub(super) config_store: Signal<crate::config::LocalConfigStore>,
    pub(super) active_account: Signal<Option<crate::config::ActiveAccountContext>>,
    pub(super) session_generation: Signal<u64>,
    pub(super) needs_device_authorization: Signal<bool>,
    pub(super) device_authorization_check_complete: Signal<bool>,
}

/// Signals the identity-creation and abandonment writes fold their outcome
/// back into.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct IdentityCreationController {
    pub(super) busy: Signal<bool>,
    pub(super) status: Signal<String>,
    pub(super) recovery_key: Signal<String>,
    pub(super) recovery_key_state: Signal<arkret_sdk::IdentityCreationRecoveryKeyState>,
    pub(super) confirmation: Signal<String>,
    pub(super) complete: Signal<bool>,
    pub(super) resume_terminal: Signal<Option<ResumeTerminal>>,
    pub(super) state_store: SyncSignal<crate::state::LocalStateStore>,
    pub(super) config_store: Signal<crate::config::LocalConfigStore>,
    pub(super) active_account: Signal<Option<crate::config::ActiveAccountContext>>,
    pub(super) token: Signal<String>,
    pub(super) session_generation: Signal<u64>,
    pub(super) principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub(super) device_id: Signal<String>,
    pub(super) needs_device_authorization: Signal<bool>,
    pub(super) device_authorization_check_complete: Signal<bool>,
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
        let Self {
            mut busy,
            mut status,
            mut words,
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
        spawn(async move {
            let result = recover_bound_principal_device(
                &handoff,
                &principal_did,
                &replacement_device_id,
                &recovery_words,
                state_store,
            )
            .await;
            words.set(String::new());
            busy.set(false);
            match result {
                Ok((recovery, completed)) => {
                    match commit_completed_account(
                        &completed,
                        &recovery_words,
                        state_store,
                        config_store,
                        active_account,
                        token,
                        &session,
                        session_generation,
                        principal_id,
                        device_id,
                        needs_device_authorization,
                        device_authorization_check_complete,
                    )
                    .await
                    {
                        Ok(()) => match clear_pending_principal_setup(state_store).await {
                            Ok(()) => {
                                status.set(format!(
                                    "Identity recovered. Device receipt {} and the Standard session grant are durable.",
                                    recovery.readiness.terminal_receipt_id
                                ));
                                if let Some(failure) = navigator.replace(Route::Dashboard) {
                                    tracing::warn!(
                                        ?failure,
                                        "recovery completion route canonicalisation failed"
                                    );
                                }
                            }
                            Err(error) => status.set(format!(
                                "Identity recovered, but local cleanup failed: {error:#}"
                            )),
                        },
                        Err(error) => status.set(format!(
                            "Recovered device could not be committed: {error:#}"
                        )),
                    }
                }
                Err(error) => status.set(format!("Recovery could not finish: {error:#}")),
            }
        });
    }
}

impl IdentityCreationController {
    /// Clear a setup this device can no longer finish and return to sign-in.
    pub(super) fn clear_stranded_setup(self, navigator: Navigator) {
        let Self {
            mut busy,
            mut status,
            state_store,
            ..
        } = self;
        spawn(async move {
            match clear_pending_principal_setup(state_store).await {
                Ok(()) => {
                    navigator.push(Route::Login);
                }
                Err(error) => status.set(format!("Could not clear this setup: {error:#}")),
            }
            busy.set(false);
        });
    }

    /// Confirm explicit abandonment of the reserved identity.
    pub(super) fn confirm_abandonment(
        self,
        handoff: crate::state::PendingAccountHandoff,
        pending: crate::state::PendingIdentityAbandonment,
        navigator: Navigator,
    ) {
        let Self {
            mut busy,
            mut status,
            mut state_store,
            ..
        } = self;
        spawn(async move {
            let result = async {
                let dpop = {
                    let mut store = state_store.write();
                    crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)?
                };
                crate::identity::identity_abandonment::confirm(&handoff, &pending, &dpop).await?;
                clear_pending_principal_setup(state_store).await
            }
            .await;
            match result {
                Ok(()) => {
                    status.set("Provisional identity abandoned. Authenticate to create a new identity root.".to_owned());
                    navigator.push(Route::Login);
                }
                Err(error) => status.set(format!("Identity abandonment failed: {error}")),
            }
            busy.set(false);
        });
    }

    /// Freeze the explicit abandonment command for user review.
    pub(super) fn prepare_abandonment(self, mut handoff: crate::state::PendingAccountHandoff) {
        let Self {
            mut busy,
            mut status,
            mut state_store,
            ..
        } = self;
        spawn(async move {
            let result = async {
                let pending = crate::identity::identity_abandonment::prepare(&handoff)?;
                handoff.identity_abandonment = Some(pending);
                let barrier = {
                    let mut store = state_store.write();
                    store.set_pending_account_handoff(Some(handoff.clone()))?;
                    store.begin_durable_flush()?
                };
                barrier.wait().await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;
            match result {
                Ok(()) => status.set(
                    "Review the identity and authenticate again before confirming abandonment."
                        .to_owned(),
                ),
                Err(error) => status.set(format!("Could not prepare abandonment: {error}")),
            }
            busy.set(false);
        });
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
        let Self {
            mut busy,
            mut status,
            mut recovery_key,
            mut recovery_key_state,
            mut confirmation,
            mut complete,
            mut resume_terminal,
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
        spawn(async move {
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
                recovery_key_state.set(confirmed_state);
                if !confirmed_state.can_control_identity() {
                    anyhow::bail!("Recovery Key is not ready for identity creation");
                }
                create_and_bind_identity(
                    &handoff,
                    &supplied_key,
                    &device,
                    state_store,
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
                        state_store,
                        config_store,
                        active_account,
                        token,
                        &session,
                        session_generation,
                        principal_id,
                        device_id,
                        needs_device_authorization,
                        device_authorization_check_complete,
                    )
                    .await
                    {
                        status.set(format!(
                            "Account completion could not be committed: {error:#}"
                        ));
                        busy.set(false);
                        return;
                    }
                    recovery_key.set(String::new());
                    recovery_key_state
                        .set(arkret_sdk::IdentityCreationRecoveryKeyState::Unavailable);
                    confirmation.set(String::new());
                    status.set(String::new());
                    complete.set(true);
                    if let Err(error) = clear_pending_principal_setup(state_store).await {
                        status.set(format!(
                            "Setup finished, but local cleanup failed: {error:#}"
                        ));
                    }
                }
                Ok(IdentityCreationCommandOutcome::Terminal(terminal)) => {
                    status.set(String::new());
                    resume_terminal.set(Some(terminal));
                }
                Err(error) => {
                    let seal_replay_contradiction = error
                        .downcast_ref::<BootstrapSealReplayContradiction>()
                        .is_some();
                    let command_error = format!("{error:#}");
                    let correlation =
                        crate::identity::account_auth::transition::LoginCorrelation::for_handoff(
                            &handoff,
                        );
                    crate::identity::account_auth::transition::record_onboarding_completion_transition(
                        crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeRestore,
                        if seal_replay_contradiction {
                            crate::identity::account_auth::transition::OnboardingCompletionOutcome::Contradiction
                        } else {
                            crate::identity::account_auth::transition::OnboardingCompletionOutcome::Failed
                        },
                        if seal_replay_contradiction {
                            "bootstrap_seal_replay_changed"
                        } else {
                            "onboarding_continuation_failed"
                        },
                        &correlation,
                        None,
                    );
                    resume_terminal.set(Some(ResumeTerminal {
                        kind: if seal_replay_contradiction {
                            ResumeTerminalKind::Contradiction
                        } else {
                            ResumeTerminalKind::RetryableFailure
                        },
                        reason: command_error,
                        inventory: Vec::new(),
                    }));
                    status.set(String::new());
                }
            }
            busy.set(false);
        });
    }
}

/// Signals the discard control folds its outcome back into.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct DiscardSetupController {
    pub(super) busy: Signal<bool>,
    pub(super) status: Signal<String>,
    pub(super) state_store: SyncSignal<crate::state::LocalStateStore>,
}

impl DiscardSetupController {
    /// Drop the unfinished setup this device holds.
    pub(super) fn discard(self, on_discard: EventHandler<()>) {
        let Self {
            mut busy,
            mut status,
            state_store,
        } = self;
        spawn(async move {
            match clear_pending_principal_setup(state_store).await {
                // Deliberately stays busy on success: the parent
                // re-routes and this control is unmounted.
                Ok(()) => on_discard.call(()),
                Err(error) => {
                    status.set(format!("Could not discard the unfinished setup: {error}"));
                    busy.set(false);
                }
            }
        });
    }
}
