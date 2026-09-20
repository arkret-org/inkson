use super::*;

#[derive(Clone, Copy, PartialEq)]
pub(super) struct RecoveryReminderEffectState {
    pub recovery_key_setup_prompt: Signal<bool>,
    pub recovery_auto_prompt_fired: Signal<bool>,
    pub token: Signal<String>,
    pub principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub sync_bootstrap_complete: Signal<bool>,
    pub secure_store_bootstrap_ready: Signal<bool>,
    pub on_onboarding_route: bool,
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
        principal_id,
        sync_bootstrap_complete,
        secure_store_bootstrap_ready,
        on_onboarding_route,
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
        // docs/user-flows-key-lifecycle.md §3/S1.
        let mut recovery_key_setup_prompt = recovery_key_setup_prompt;
        let mut recovery_auto_prompt_fired = recovery_auto_prompt_fired;
        use_effect(move || {
            if recovery_auto_prompt_fired() || recovery_key_setup_prompt() {
                return;
            }
            if !secure_store_bootstrap_ready() {
                return;
            }
            let session = token();
            if principal_id().is_none() {
                return;
            }
            if session.trim().is_empty() {
                return;
            }
            // Recovery setup publishes account-authority policy and therefore
            // requires an enrollment-capable session grant. Keep this guard in
            // the extracted effect; without it a session lacking that grant
            // opens a modal that can only fail with device_unauthorized.
            if state_store.read().session_grant().is_none() {
                return;
            }
            let (inputs, already_prompted) = {
                let store = state_store.read();
                let account_recovery_configured = account_recovery_configured();
                let local_recovery_configured =
                    crate::views::recovery::recovery_options_configured(&store);
                let inputs = crate::account_health::AccountHealthInputs {
                    has_session: true,
                    sync_bootstrap_complete: sync_bootstrap_complete(),
                    device_check_complete: device_authorization_check_complete(),
                    on_recovery_route: false,
                    on_onboarding_route,
                    recovery_check_complete: account_recovery_configured.is_some(),
                    needs_device_authorization: needs_device_authorization(),
                    account_has_other_devices: account_has_other_devices(),
                    needs_mls_unlock: needs_mls_unlock(),
                    needs_mls_backup: needs_mls_backup(),
                    needs_mls_recovery_setup: needs_mls_recovery_setup(),
                    recovery_unconfigured: recovery_setup_prompt_required_for_account_state(
                        account_recovery_configured,
                        local_recovery_configured,
                        account_has_other_devices(),
                    ),
                };
                let already =
                    recovery_auto_prompt_already_prompted(&store, account_recovery_configured);
                (inputs, already)
            };
            if crate::account_health::should_auto_prompt_recovery_setup(inputs, already_prompted) {
                recovery_auto_prompt_fired.set(true);
                recovery_key_setup_prompt.set(true);
            }
        });
    }
    rsx! {}
}
