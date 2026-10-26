use std::rc::Rc;

use glory::prelude::*;

use super::*;
use crate::presentation::InksonContext;

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

struct OwnedRecoveryCompletionState {
    account_recovery_configured: Cage<Option<bool>>,
    account_recovery_detection_key_seen: Cage<Option<String>>,
    account_recovery_retry_attempt: Cage<u8>,
}

impl RecoveryCompletionState for OwnedRecoveryCompletionState {
    fn set_configured(&mut self, configured: Option<bool>) {
        {
            let next_value = configured;
            self.account_recovery_configured
                .revise(|current| *current = next_value)
        };
    }

    fn detection_key(&self) -> Option<String> {
        self.account_recovery_detection_key_seen.get()
    }

    fn set_detection_key(&mut self, detection_key: Option<String>) {
        {
            let next_value = detection_key;
            self.account_recovery_detection_key_seen
                .revise(|current| *current = next_value)
        };
    }

    fn retry_attempt(&self) -> u8 {
        self.account_recovery_retry_attempt.get()
    }

    fn set_retry_attempt(&mut self, attempt: u8) {
        {
            let next_value = attempt;
            self.account_recovery_retry_attempt
                .revise(|current| *current = next_value)
        };
    }
}

/// Tracks whether the authenticated account has a server-side recovery path.
/// The result feeds account-health reminders; transport and session invalidation
/// stay owned by the mounted session shell instead of route rendering.
pub(super) fn install(scope: &Scope, context: Rc<InksonContext>) {
    let account_recovery_configured = context.account_recovery_configured;
    let account_recovery_detection_key_seen = scope.cage(None::<String>);
    let account_recovery_retry_attempt = scope.cage(0_u8);
    let last_error = context.last_error;
    let token = context.token;
    let principal_id = context.principal_id;
    let device_id = context.device_id;
    let sync_generation = context.sync_generation;
    let session_boot_state = context.session_boot_state;
    let active_account = context.active_account;
    let base_url = context.base_url;
    let session_generation = context.session_generation;
    let route = context.route;
    let state_revision = context.state_revision;
    let session_coordinator = context.services.session.clone();
    let task_scope = scope.clone();
    scope.effect(move || {
        let _ = state_revision.get();
        let state_store = context.state_store.clone();
        let on_onboarding_route = matches!(route.get(), crate::routes::Route::Onboarding);

        if on_onboarding_route {
            // The onboarding flow owns recovery publication and its progress
            // UI. Probing the same backup collection here races that flow and
            // turns its final transition into redundant network traffic.
            { let next_value = None; account_recovery_configured.revise(|current| *current = next_value) };
            { let next_value = None; account_recovery_detection_key_seen.revise(|current| *current = next_value) };
            { let next_value = 0; account_recovery_retry_attempt.revise(|current| *current = next_value) };
            return;
        }
        let base = base_url.get();
        let credential = token.get();
        let actor = principal_id.get();
        let Some(actor_id) = actor.clone() else {
            { let next_value = None; account_recovery_configured.revise(|current| *current = next_value) };
            { let next_value = None; account_recovery_detection_key_seen.revise(|current| *current = next_value) };
            { let next_value = 0; account_recovery_retry_attempt.revise(|current| *current = next_value) };
            return;
        };
        let Some(account) = active_account.get() else {
            { let next_value = None; account_recovery_configured.revise(|current| *current = next_value) };
            { let next_value = None; account_recovery_detection_key_seen.revise(|current| *current = next_value) };
            { let next_value = 0; account_recovery_retry_attempt.revise(|current| *current = next_value) };
            return;
        };
        let generation = sync_generation.get();
        let ui_session_generation = session_generation.get();
        let coordinator_generation = session_coordinator.generation();
        if !matches!(session_boot_state.get(), SessionBootState::Authenticated)
            || base.trim().is_empty()
            || credential.trim().is_empty()
        {
            { let next_value = None; account_recovery_configured.revise(|current| *current = next_value) };
            { let next_value = None; account_recovery_detection_key_seen.revise(|current| *current = next_value) };
            { let next_value = 0; account_recovery_retry_attempt.revise(|current| *current = next_value) };
            return;
        }
        let recovery_material_evidence = state_store.read(|store| store.recovery_material_evidence());
        let gate_authority = account.authority.clone();
        let gate_device = device_id.get();
        let evidence_fingerprint = recovery_material_evidence
            .as_ref()
            .and_then(|evidence| arkret_sdk::canonical::canonical_json_bytes(evidence).ok())
            .map(|bytes| arkret_sdk::canonical::sha256_hex(&bytes))
            .unwrap_or_default();
        let detection_key = format!(
            "{ui_session_generation}|{generation}|{base}|{actor_id}|{}|{gate_device}|{evidence_fingerprint}",
            gate_authority.station_id,
        );
        if account_recovery_detection_key_seen.get().as_deref() == Some(detection_key.as_str()) {
            return;
        }
        { let next_value = Some(detection_key.clone()); account_recovery_detection_key_seen.revise(|current| *current = next_value) };
        tracing::debug!(target: "recovery_diag", key = %detection_key, "recovery_state re-fetch (authoritative recovery policy)");
        let remember_authority = gate_authority.clone();
        let remember_device = gate_device.clone();
        let session_coordinator = session_coordinator.clone();
        if let Err(error) = crate::runtime_helpers::spawn_owned(&task_scope, async move {
            let result =
                crate::transport::auth::with_authed_api(&base, credential, |api| async move {
                    let policy = api.get_recovery_policy().await?;
                    let gate_verification = match recovery_material_evidence.as_ref() {
                        Some(evidence)
                            if evidence.account_id == gate_authority
                                && evidence.device_id.as_str() == gate_device =>
                        {
                            Some(
                                crate::recovery_flow::verify_recovery_material_evidence(
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
            let mut completion_state = OwnedRecoveryCompletionState {
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
                        crate::recovery_flow::active_recovery_policy(&policy).is_some();
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
                            &remember_authority,
                            &remember_device,
                        );
                    }
                    if let Some(error) = gate_error {
                        { let next_value = Some(error); last_error.revise(|current| *current = next_value) };
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
                            session_coordinator.invalidate_if_generation(
                                coordinator_generation,
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
                        session_coordinator.invalidate_if_generation(
                            coordinator_generation,
                            "session expired while loading account recovery state",
                        );
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
                        { let next_value = Some(format!("recovery_state: {}", error.display())); last_error.revise(|current| *current = next_value) };
                        crate::runtime_helpers::sleep_for(recovery_state_retry_delay(attempt))
                            .await;
                        clear_completed_recovery_request_for_retry(
                            &mut completion_state,
                            &detection_key,
                        );
                    }
                }
            }
        }) { task_scope.report_error(error); }
    });
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
