use super::*;

#[derive(Clone, Copy, PartialEq)]
pub(super) struct RecoveryReminderEffectState {
    pub recovery_key_setup_prompt: Signal<bool>,
    pub recovery_auto_prompt_fired: Signal<bool>,
    pub token: Signal<String>,
    pub account_did: Signal<String>,
    pub sync_bootstrap_complete: Signal<bool>,
    pub device_authorization_check_complete: Signal<bool>,
    pub account_recovery_configured: Signal<Option<bool>>,
    pub needs_device_authorization: Signal<bool>,
    pub needs_mls_unlock: Signal<bool>,
    pub needs_mls_backup: Signal<bool>,
    pub needs_mls_recovery_setup: Signal<bool>,
    pub account_has_other_devices: Signal<bool>,
}

#[component]
pub(super) fn RecoveryReminderEffects(state: RecoveryReminderEffectState) -> Element {
    let RecoveryReminderEffectState {
        recovery_key_setup_prompt,
        recovery_auto_prompt_fired,
        token,
        account_did,
        sync_bootstrap_complete,
        device_authorization_check_complete,
        account_recovery_configured,
        needs_device_authorization,
        needs_mls_unlock,
        needs_mls_backup,
        needs_mls_recovery_setup,
        account_has_other_devices,
    } = state;
    let SessionContext { state_store, .. } = SessionContext::get();

    {
        // Proactive one-time 24-word Recovery Key setup nudge for new users.
        // When the account is otherwise healthy but no recovery path is
        // configured (the RecoverySetupReminder state), open the setup modal
        // once and persist a flag so it never auto-pops again — the passive
        // dashboard banner remains as the steady-state reminder. The
        // in-memory `recovery_auto_prompt_fired` guard makes "once" robust within
        // a session. See account_health::should_auto_prompt_recovery_setup and
        // docs/user-strands-key-lifecycle.md §3/S1.
        let mut recovery_key_setup_prompt = recovery_key_setup_prompt;
        let mut recovery_auto_prompt_fired = recovery_auto_prompt_fired;
        let mut state_store = state_store;
        use_effect(move || {
            if recovery_auto_prompt_fired() || recovery_key_setup_prompt() {
                return;
            }
            let session = token();
            let actor = account_did();
            if session.trim().is_empty() || actor.trim().is_empty() {
                return;
            }
            let (inputs, already_prompted, local_only_fingerprint) = {
                let store = state_store.read();
                let account_recovery_configured = account_recovery_configured();
                let local_recovery_configured =
                    crate::views::recovery::recovery_options_configured(&store, &actor);
                let local_only_fingerprint = recovery_auto_prompt_pending_local_only_fingerprint(
                    &store,
                    &actor,
                    account_recovery_configured,
                );
                let inputs = crate::account_health::AccountHealthInputs {
                    has_session: true,
                    sync_bootstrap_complete: sync_bootstrap_complete(),
                    device_check_complete: device_authorization_check_complete(),
                    // Route doesn't gate this one-time nudge; the guards do.
                    on_recovery_route: false,
                    recovery_check_complete: account_recovery_configured.is_some(),
                    needs_device_authorization: needs_device_authorization(),
                    needs_mls_unlock: needs_mls_unlock(),
                    needs_mls_backup: needs_mls_backup(),
                    needs_mls_recovery_setup: needs_mls_recovery_setup(),
                    floor_low:
                        crate::components::encryption_floor_prompt::account_needs_recommended_encryption_prompt(
                            &store, &actor,
                        ),
                    recovery_unconfigured: recovery_setup_prompt_required_for_account_state(
                        account_recovery_configured,
                        local_recovery_configured,
                        account_has_other_devices(),
                    ),
                };
                let already = recovery_auto_prompt_already_prompted(
                    &store,
                    &actor,
                    account_recovery_configured,
                );
                (inputs, already, local_only_fingerprint)
            };
            if crate::account_health::should_auto_prompt_recovery_setup(inputs, already_prompted) {
                recovery_auto_prompt_fired.set(true);
                let mut store = state_store.write();
                store.save_private_data(&actor, RECOVERY_AUTO_PROMPT_SHOWN_KEY, "1".to_owned());
                if let Some(fingerprint) = local_only_fingerprint {
                    store.save_private_data(
                        &actor,
                        RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY,
                        fingerprint,
                    );
                }
                recovery_key_setup_prompt.set(true);
            }
        });
    }
    rsx! {}
}
