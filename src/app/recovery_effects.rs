use super::*;

fn recovery_state_retry_delay(attempt: u8) -> std::time::Duration {
    let exponent = u32::from(attempt.saturating_sub(1).min(5));
    std::time::Duration::from_secs(1_u64 << exponent)
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
            // Recovery publication explicitly clears this key. Do not let an
            // older in-flight read overwrite the accepted `Some(true)` result
            // with the pre-publication policy snapshot; the cleared key also
            // schedules an authoritative re-fetch of the new generation.
            if account_recovery_detection_key_seen().as_deref() != Some(detection_key.as_str()) {
                return;
            }
            match result {
                Ok((policy, gate_verification)) => {
                    let mut retry_gate_verification = false;
                    if let Some(gate_verification) = gate_verification {
                        match gate_verification {
                            Ok(()) => crate::event_submit::remember_verified_recovery_gate(
                                remember_actor.as_str(),
                                &remember_device,
                            ),
                            Err(error) if crate::api_error::is_auth_expired_error(&error) => {
                                session_coordinator.invalidate(
                                    "session expired while verifying recovery material evidence",
                                );
                                account_recovery_configured.set(None);
                                return;
                            }
                            Err(error) => {
                                retry_gate_verification = true;
                                last_error.set(Some(format!(
                                    "recovery_material_evidence: {}",
                                    crate::api_error::display_with_reason_detail(&error)
                                )));
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
                    account_recovery_configured.set(Some(recovery_configured));
                    if retry_gate_verification {
                        // The accepted policy remains authoritative for the UI,
                        // while the independent local-evidence rail retries
                        // until Event submission can cache the verified PCR
                        // bootstrap basis as well.
                        let attempt = account_recovery_retry_attempt().saturating_add(1);
                        account_recovery_retry_attempt.set(attempt);
                        crate::runtime_helpers::sleep_for(recovery_state_retry_delay(attempt))
                            .await;
                        if account_recovery_detection_key_seen().as_deref()
                            == Some(detection_key.as_str())
                        {
                            account_recovery_detection_key_seen.set(None);
                        }
                    } else {
                        account_recovery_retry_attempt.set(0);
                    }
                }
                Err(error) if error.is_auth_expired() => {
                    session_coordinator
                        .invalidate("session expired while loading account recovery state");
                    account_recovery_configured.set(None);
                }
                Err(error) => {
                    last_error.set(Some(format!("recovery_state: {}", error.display())));
                    account_recovery_configured.set(None);
                    let attempt = account_recovery_retry_attempt().saturating_add(1);
                    account_recovery_retry_attempt.set(attempt);
                    crate::runtime_helpers::sleep_for(recovery_state_retry_delay(attempt)).await;
                    if account_recovery_detection_key_seen().as_deref()
                        == Some(detection_key.as_str())
                    {
                        account_recovery_detection_key_seen.set(None);
                    }
                }
            }
        });
    });

    rsx! {}
}

#[cfg(test)]
mod tests {
    use super::recovery_state_retry_delay;

    #[test]
    fn recovery_state_retry_uses_bounded_exponential_backoff() {
        assert_eq!(recovery_state_retry_delay(1).as_secs(), 1);
        assert_eq!(recovery_state_retry_delay(2).as_secs(), 2);
        assert_eq!(recovery_state_retry_delay(6).as_secs(), 32);
        assert_eq!(recovery_state_retry_delay(u8::MAX).as_secs(), 32);
    }
}
