use std::rc::Rc;

use glory::prelude::*;

use super::*;
use crate::presentation::InksonContext;

pub(super) fn install(scope: &Scope, context: Rc<InksonContext>) {
    let recovery_key_setup_prompt = context.recovery_key_setup_open;
    let recovery_auto_prompt_fired = scope.cage(false);
    let token = context.token;
    let principal_id = context.principal_id;
    let sync_bootstrap_complete = context.sync_bootstrap_complete;
    let secure_store_bootstrap_ready = context.secure_store_bootstrap_ready;
    let device_authorization_check_complete = context.device_authorization_check_complete;
    let account_recovery_configured = context.account_recovery_configured;
    let needs_device_authorization = context.needs_device_authorization;
    let needs_mls_unlock = context.needs_mls_unlock;
    let needs_mls_backup = context.needs_mls_backup;
    let needs_mls_recovery_setup = context.needs_mls_recovery_setup;
    let account_has_other_devices = context.account_has_other_devices;
    let route = context.route;
    {
        // Proactive one-time 24-word Recovery Key setup nudge for new users.
        // When the account is otherwise healthy but no recovery path is
        // configured (the RecoverySetupReminder state), open the setup modal
        // once and persist a flag so it never auto-pops again — the passive
        // dashboard banner remains as the steady-state reminder. The
        // in-memory `recovery_auto_prompt_fired` guard makes "once" robust within
        // a session. See account_health::should_auto_prompt_recovery_setup and
        // docs/user-flows-key-lifecycle.md §3/S1.
        scope.effect(move || {
            let _ = context.state_revision.get();
            let state_store = &context.state_store;
            let on_onboarding_route = matches!(route.get(), crate::routes::Route::Onboarding);
            if recovery_auto_prompt_fired.get() || recovery_key_setup_prompt.get() {
                return;
            }
            if !secure_store_bootstrap_ready.get() {
                return;
            }
            let session = token.get();
            if principal_id.get().is_none() {
                return;
            }
            if session.trim().is_empty() {
                return;
            }
            // Recovery setup publishes account-authority policy and therefore
            // requires an enrollment-capable session grant. Keep this guard in
            // the extracted effect; without it a session lacking that grant
            // opens a modal that can only fail with device_unauthorized.
            if state_store.read(|store| store.session_grant().is_none()) {
                return;
            }
            let (inputs, already_prompted) = state_store.read(|store| {
                let account_recovery_configured = account_recovery_configured.get();
                let local_recovery_configured =
                    crate::views::recovery::recovery_options_configured(store);
                let inputs = crate::account_health::AccountHealthInputs {
                    has_session: true,
                    sync_bootstrap_complete: sync_bootstrap_complete.get(),
                    device_check_complete: device_authorization_check_complete.get(),
                    on_recovery_route: false,
                    on_onboarding_route,
                    recovery_check_complete: account_recovery_configured.is_some(),
                    needs_device_authorization: needs_device_authorization.get(),
                    account_has_other_devices: account_has_other_devices.get(),
                    needs_mls_unlock: needs_mls_unlock.get(),
                    needs_mls_backup: needs_mls_backup.get(),
                    needs_mls_recovery_setup: needs_mls_recovery_setup.get(),
                    recovery_unconfigured: recovery_setup_prompt_required_for_account_state(
                        account_recovery_configured,
                        local_recovery_configured,
                        account_has_other_devices.get(),
                    ),
                };
                let already =
                    recovery_auto_prompt_already_prompted(store, account_recovery_configured);
                (inputs, already)
            });
            if crate::account_health::should_auto_prompt_recovery_setup(inputs, already_prompted) {
                {
                    let next_value = true;
                    recovery_auto_prompt_fired.revise(|current| *current = next_value)
                };
                {
                    let next_value = true;
                    recovery_key_setup_prompt.revise(|current| *current = next_value)
                };
            }
        });
    }
}
