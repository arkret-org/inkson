use super::*;

/// Tracks whether the authenticated account has a server-side recovery path.
/// The result feeds account-health reminders; transport and session invalidation
/// stay owned by the mounted session shell instead of route rendering.
#[component]
pub(super) fn AccountRecoveryEffects(
    mut account_recovery_configured: Signal<Option<bool>>,
    mut account_recovery_detection_key_seen: Signal<Option<String>>,
    mut last_error: Signal<Option<String>>,
    token: Signal<String>,
    principal_id: Signal<String>,
    device_id: Signal<String>,
    sync_generation: Signal<u64>,
    session_boot_state: Signal<SessionBootState>,
    on_onboarding_route: bool,
) -> Element {
    let SessionContext {
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
            return;
        }
        let base = base_url();
        let credential = token();
        let actor = principal_id();
        let generation = sync_generation();
        if !matches!(session_boot_state(), SessionBootState::Authenticated)
            || base.trim().is_empty()
            || credential.trim().is_empty()
            || actor.trim().is_empty()
        {
            account_recovery_configured.set(None);
            account_recovery_detection_key_seen.set(None);
            return;
        }
        let detection_key = format!("{generation}|{base}|{actor}");
        if account_recovery_detection_key_seen().as_deref() == Some(detection_key.as_str()) {
            return;
        }
        account_recovery_detection_key_seen.set(Some(detection_key.clone()));
        tracing::debug!(target: "recovery_diag", key = %detection_key, "recovery_state re-fetch (recovery-policy+backups)");
        let local_fingerprint = {
            let store = state_store.read();
            crate::views::recovery::local_recovery_key_fingerprint(&store, &actor)
        };
        let recovery_material_evidence = state_store.read().recovery_material_evidence();
        let gate_actor = actor.clone();
        let gate_device = device_id();
        let remember_actor = actor.clone();
        let remember_device = gate_device.clone();
        let session_coordinator = session_coordinator.clone();
        spawn(async move {
            match crate::transport::auth::with_authed_api(&base, credential, |api| async move {
                let policy = serde_json::to_value(&api.get_recovery_policy().await?)?;
                let backups = serde_json::to_value(&api.list_key_backups().await?)?;
                let gate_verified = match recovery_material_evidence.as_ref() {
                    Some(evidence)
                        if evidence.principal_id.as_str() == gate_actor
                            && evidence.device_id.as_str() == gate_device =>
                    {
                        crate::recovery_strand::verify_recovery_material_evidence(&api, evidence)
                            .await?;
                        true
                    }
                    _ => false,
                };
                Ok::<(serde_json::Value, serde_json::Value, bool), anyhow::Error>((
                    policy,
                    backups,
                    gate_verified,
                ))
            })
            .await
            {
                Ok((policy, backups, gate_verified)) => {
                    if gate_verified {
                        crate::event_submit::remember_verified_recovery_gate(
                            &remember_actor,
                            &remember_device,
                        );
                    }
                    let state = crate::recovery_strand::account_recovery_state_from_payloads(
                        &policy,
                        &backups,
                        local_fingerprint,
                    );
                    account_recovery_configured.set(Some(state.server_recovery_configured()));
                }
                Err(error) if error.is_auth_expired() => {
                    session_coordinator
                        .invalidate("session expired while loading account recovery state");
                    account_recovery_configured.set(None);
                }
                Err(error) => {
                    last_error.set(Some(format!("recovery_state: {}", error.display())));
                    account_recovery_configured.set(None);
                }
            }
        });
    });

    rsx! {}
}
