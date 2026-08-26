use super::*;

fn recovery_state_retry_delay(attempt: u8) -> std::time::Duration {
    let exponent = u32::from(attempt.saturating_sub(1).min(5));
    std::time::Duration::from_secs(1_u64 << exponent)
}

fn recovery_request_is_current(current_detection_key: Option<&str>, completed_key: &str) -> bool {
    current_detection_key == Some(completed_key)
}

#[derive(Clone, Copy)]
enum RecoveryRequestCompletion {
    Success {
        configured: bool,
        retry_gate_verification: bool,
    },
    Failure,
    AuthFailure,
}

#[derive(Debug, PartialEq, Eq)]
enum RecoveryCompletionAction {
    Stale,
    Complete,
    Retry { attempt: u8 },
    InvalidateSession,
}

trait RecoveryCompletionState {
    fn set_configured(&mut self, configured: Option<bool>);
    fn detection_key(&self) -> Option<String>;
    fn set_detection_key(&mut self, detection_key: Option<String>);
    fn retry_attempt(&self) -> u8;
    fn set_retry_attempt(&mut self, attempt: u8);
}

fn apply_recovery_request_completion(
    state: &mut impl RecoveryCompletionState,
    completed_key: &str,
    completion: RecoveryRequestCompletion,
) -> RecoveryCompletionAction {
    if !recovery_request_is_current(state.detection_key().as_deref(), completed_key) {
        return RecoveryCompletionAction::Stale;
    }
    match completion {
        RecoveryRequestCompletion::Success {
            configured,
            retry_gate_verification,
        } => {
            state.set_configured(Some(configured));
            if retry_gate_verification {
                let attempt = state.retry_attempt().saturating_add(1);
                state.set_retry_attempt(attempt);
                RecoveryCompletionAction::Retry { attempt }
            } else {
                state.set_retry_attempt(0);
                RecoveryCompletionAction::Complete
            }
        }
        RecoveryRequestCompletion::Failure => {
            state.set_configured(None);
            let attempt = state.retry_attempt().saturating_add(1);
            state.set_retry_attempt(attempt);
            RecoveryCompletionAction::Retry { attempt }
        }
        RecoveryRequestCompletion::AuthFailure => {
            state.set_configured(None);
            RecoveryCompletionAction::InvalidateSession
        }
    }
}

fn clear_completed_recovery_request_for_retry(
    state: &mut impl RecoveryCompletionState,
    completed_key: &str,
) {
    if recovery_request_is_current(state.detection_key().as_deref(), completed_key) {
        state.set_detection_key(None);
    }
}

struct SignalRecoveryCompletionState {
    account_recovery_configured: Signal<Option<bool>>,
    account_recovery_detection_key_seen: Signal<Option<String>>,
    account_recovery_retry_attempt: Signal<u8>,
}

impl RecoveryCompletionState for SignalRecoveryCompletionState {
    fn set_configured(&mut self, configured: Option<bool>) {
        self.account_recovery_configured.set(configured);
    }

    fn detection_key(&self) -> Option<String> {
        (self.account_recovery_detection_key_seen)()
    }

    fn set_detection_key(&mut self, detection_key: Option<String>) {
        self.account_recovery_detection_key_seen.set(detection_key);
    }

    fn retry_attempt(&self) -> u8 {
        (self.account_recovery_retry_attempt)()
    }

    fn set_retry_attempt(&mut self, attempt: u8) {
        self.account_recovery_retry_attempt.set(attempt);
    }
}

/// Tracks whether the authenticated account has a server-side recovery path.
/// The result feeds account-health reminders; transport and session invalidation
/// stay owned by the mounted session shell instead of route rendering.
#[component]
pub(super) fn AccountRecoveryEffects(
    mut account_recovery_configured: Signal<Option<bool>>,
    mut account_recovery_detection_key_seen: Signal<Option<String>>,
    mut account_recovery_retry_attempt: Signal<u8>,
    mut last_error: Signal<Option<String>>,
    token: Signal<String>,
    principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    device_id: Signal<String>,
    sync_generation: Signal<u64>,
    session_boot_state: Signal<SessionBootState>,
    on_onboarding_route: bool,
) -> Element {
    let SessionContext {
        active_account,
        state_store,
        base_url,
        ..
    } = SessionContext::get();
    let runtime_services = use_context::<crate::runtime::services::RuntimeServices>();
    let session_coordinator = runtime_services.session.clone();

    use_effect(move || {
        if on_onboarding_route {
            // The onboarding flow owns recovery publication and its progress
            // UI. Probing the same backup collection here races that flow and
            // turns its final transition into redundant network traffic.
            account_recovery_configured.set(None);
            account_recovery_detection_key_seen.set(None);
            account_recovery_retry_attempt.set(0);
            return;
        }
        let base = base_url();
        let credential = token();
        let actor = principal_id();
        let Some(actor_id) = actor.clone() else {
            account_recovery_configured.set(None);
            account_recovery_detection_key_seen.set(None);
            account_recovery_retry_attempt.set(0);
            return;
        };
        let Some(account) = active_account() else {
            account_recovery_configured.set(None);
            account_recovery_detection_key_seen.set(None);
            account_recovery_retry_attempt.set(0);
            return;
        };
        let generation = sync_generation();
        if !matches!(session_boot_state(), SessionBootState::Authenticated)
            || base.trim().is_empty()
            || credential.trim().is_empty()
        {
            account_recovery_configured.set(None);
            account_recovery_detection_key_seen.set(None);
            account_recovery_retry_attempt.set(0);
            return;
        }
        let detection_key = format!("{generation}|{base}|{actor_id}");
        if account_recovery_detection_key_seen().as_deref() == Some(detection_key.as_str()) {
            return;
        }
        account_recovery_detection_key_seen.set(Some(detection_key.clone()));
        tracing::debug!(target: "recovery_diag", key = %detection_key, "recovery_state re-fetch (authoritative recovery policy)");
        let recovery_material_evidence = state_store.read().recovery_material_evidence();
        let gate_actor = account.full_id().clone();
        let gate_device = device_id();
        let remember_actor = actor_id;
        let remember_device = gate_device.clone();
        let session_coordinator = session_coordinator.clone();
        spawn(async move {
            let result =
                crate::transport::auth::with_authed_api(&base, credential, |api| async move {
                    let policy = api.get_recovery_policy().await?;
                    let gate_verification = match recovery_material_evidence.as_ref() {
                        Some(evidence)
                            if evidence.principal_id == gate_actor
                                && evidence.device_id.as_str() == gate_device =>
                        {
                            Some(
                                crate::recovery_strand::verify_recovery_material_evidence(
                                    &api, evidence,
                                )
                                .await,
                            )
                        }
                        _ => None,
                    };
                    Ok::<_, anyhow::Error>((policy, gate_verification))
                })
                .await;
            let mut completion_state = SignalRecoveryCompletionState {
                account_recovery_configured,
                account_recovery_detection_key_seen,
                account_recovery_retry_attempt,
            };
            match result {
                Ok((policy, gate_verification)) => {
                    let mut retry_gate_verification = false;
                    let mut remember_verified_gate = false;
                    let mut gate_error = None;
                    let mut gate_auth_expired = false;
                    if let Some(gate_verification) = gate_verification {
                        match gate_verification {
                            Ok(()) => remember_verified_gate = true,
                            Err(error) if crate::api_error::is_auth_expired_error(&error) => {
                                gate_auth_expired = true;
                            }
                            Err(error) => {
                                retry_gate_verification = true;
                                gate_error = Some(format!(
                                    "recovery_material_evidence: {}",
                                    crate::api_error::display_with_reason_detail(&error)
                                ));
                            }
                        }
                    }
                    // Realm creation is gated by the accepted Recovery Policy,
                    // not by the independently retryable ciphertext-backup
                    // collection. A failed backup list/upload must not erase an
                    // authoritative policy result and strand the UI in
                    // `Checking` forever.
                    let recovery_configured =
                        crate::recovery_strand::active_recovery_policy(&policy).is_some();
                    let completion = if gate_auth_expired {
                        RecoveryRequestCompletion::AuthFailure
                    } else {
                        RecoveryRequestCompletion::Success {
                            configured: recovery_configured,
                            retry_gate_verification,
                        }
                    };
                    let action = apply_recovery_request_completion(
                        &mut completion_state,
                        &detection_key,
                        completion,
                    );
                    if action == RecoveryCompletionAction::Stale {
                        return;
                    }
                    if remember_verified_gate {
                        crate::event_submit::remember_verified_recovery_gate(
                            remember_actor.as_str(),
                            &remember_device,
                        );
                    }
                    if let Some(error) = gate_error {
                        last_error.set(Some(error));
                    }
                    match action {
                        RecoveryCompletionAction::Retry { attempt } => {
                            // The accepted policy remains authoritative for the UI,
                            // while the independent local-evidence rail retries
                            // until Event submission can cache the verified PCR
                            // bootstrap basis as well.
                            crate::runtime_helpers::sleep_for(recovery_state_retry_delay(attempt))
                                .await;
                            clear_completed_recovery_request_for_retry(
                                &mut completion_state,
                                &detection_key,
                            );
                        }
                        RecoveryCompletionAction::InvalidateSession => {
                            session_coordinator.invalidate(
                                "session expired while verifying recovery material evidence",
                            );
                        }
                        RecoveryCompletionAction::Complete | RecoveryCompletionAction::Stale => {}
                    }
                }
                Err(error) if error.is_auth_expired() => {
                    if apply_recovery_request_completion(
                        &mut completion_state,
                        &detection_key,
                        RecoveryRequestCompletion::AuthFailure,
                    ) == RecoveryCompletionAction::InvalidateSession
                    {
                        session_coordinator
                            .invalidate("session expired while loading account recovery state");
                    }
                }
                Err(error) => {
                    if let RecoveryCompletionAction::Retry { attempt } =
                        apply_recovery_request_completion(
                            &mut completion_state,
                            &detection_key,
                            RecoveryRequestCompletion::Failure,
                        )
                    {
                        last_error.set(Some(format!("recovery_state: {}", error.display())));
                        crate::runtime_helpers::sleep_for(recovery_state_retry_delay(attempt))
                            .await;
                        clear_completed_recovery_request_for_retry(
                            &mut completion_state,
                            &detection_key,
                        );
                    }
                }
            }
        });
    });

    rsx! {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct TestRecoverySignals {
        configured: Option<bool>,
        detection_key: Option<String>,
        retry_attempt: u8,
    }

    impl RecoveryCompletionState for TestRecoverySignals {
        fn set_configured(&mut self, configured: Option<bool>) {
            self.configured = configured;
        }

        fn detection_key(&self) -> Option<String> {
            self.detection_key.clone()
        }

        fn set_detection_key(&mut self, detection_key: Option<String>) {
            self.detection_key = detection_key;
        }

        fn retry_attempt(&self) -> u8 {
            self.retry_attempt
        }

        fn set_retry_attempt(&mut self, attempt: u8) {
            self.retry_attempt = attempt;
        }
    }

    fn new_generation_signals() -> TestRecoverySignals {
        TestRecoverySignals {
            configured: Some(true),
            detection_key: Some("generation-2".to_owned()),
            retry_attempt: 0,
        }
    }

    #[test]
    fn recovery_state_retry_uses_bounded_exponential_backoff() {
        assert_eq!(recovery_state_retry_delay(1).as_secs(), 1);
        assert_eq!(recovery_state_retry_delay(2).as_secs(), 2);
        assert_eq!(recovery_state_retry_delay(6).as_secs(), 32);
        assert_eq!(recovery_state_retry_delay(u8::MAX).as_secs(), 32);
    }

    #[test]
    fn recovery_state_stale_completions_cannot_mutate_new_generation_signals() {
        for completion in [
            RecoveryRequestCompletion::Success {
                configured: false,
                retry_gate_verification: false,
            },
            RecoveryRequestCompletion::Failure,
            RecoveryRequestCompletion::AuthFailure,
        ] {
            let mut signals = new_generation_signals();
            assert_eq!(
                apply_recovery_request_completion(&mut signals, "generation-1", completion),
                RecoveryCompletionAction::Stale
            );
            assert_eq!(signals, new_generation_signals());
        }
    }

    #[test]
    fn recovery_state_current_success_updates_state_and_resets_retry() {
        let mut signals = new_generation_signals();
        signals.configured = None;
        signals.retry_attempt = 3;

        assert_eq!(
            apply_recovery_request_completion(
                &mut signals,
                "generation-2",
                RecoveryRequestCompletion::Success {
                    configured: true,
                    retry_gate_verification: false,
                },
            ),
            RecoveryCompletionAction::Complete
        );

        assert_eq!(signals.configured, Some(true));
        assert_eq!(signals.retry_attempt, 0);
        assert_eq!(signals.detection_key.as_deref(), Some("generation-2"));
    }

    #[test]
    fn recovery_state_current_failure_clears_state_and_schedules_retry() {
        let mut signals = new_generation_signals();

        assert_eq!(
            apply_recovery_request_completion(
                &mut signals,
                "generation-2",
                RecoveryRequestCompletion::Failure,
            ),
            RecoveryCompletionAction::Retry { attempt: 1 }
        );
        clear_completed_recovery_request_for_retry(&mut signals, "generation-2");

        assert_eq!(signals.configured, None);
        assert_eq!(signals.retry_attempt, 1);
        assert_eq!(signals.detection_key, None);
    }

    #[test]
    fn recovery_state_current_auth_failure_invalidates_and_clears_state() {
        let mut signals = new_generation_signals();

        assert_eq!(
            apply_recovery_request_completion(
                &mut signals,
                "generation-2",
                RecoveryRequestCompletion::AuthFailure,
            ),
            RecoveryCompletionAction::InvalidateSession
        );

        assert_eq!(signals.configured, None);
        assert_eq!(signals.detection_key.as_deref(), Some("generation-2"));
    }
}
