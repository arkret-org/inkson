//! Account-health prompt resolver.
//!
//! After session boot, several mutually-dependent account-setup conditions can
//! be true at once (device not yet authorized, encrypted history that this
//! browser cannot decrypt, missing server backup, no recovery key, …).
//! Historically each prompt component re-derived its own suppression condition
//! inline in `app.rs`, so multiple banners could stack.
//!
//! This module centralizes the decision: given the boolean state variables, it
//! returns the single highest-priority prompt that should be visible. The
//! priority order is the canonical "account health check" chain documented in
//! `docs/user-flows-key-lifecycle.md` §3.

/// The single prompt that should be visible, in strict descending priority.
///
/// `Ord` is derived so the enum's declaration order *is* the priority order
/// (lower discriminant = higher priority). Callers gate each prompt's render
/// on `resolve(..) == Variant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccountHealthPrompt {
    /// 1. This device is not yet a long-term authorized device. Everything else is blocked until
    ///    pairing/recovery promotes it. (`needs_device_authorization`)
    DeviceAuthorization,
    /// 2. The server holds an account-secret backup but this device has no local material —
    ///    encrypted history can be restored by unlocking it. (`needs_mls_unlock`)
    MlsUnlock,
    /// 3. This device has encrypted material but the server has no backup yet — a fresh browser
    ///    would lose history; publish a backup now. (`needs_mls_backup`)
    MlsBackup,
    /// 4. Encrypted history exists but there is nothing this browser can decrypt and no recovery
    ///    path is configured (S5 dead-end diagnostic). (`needs_mls_recovery_setup`)
    RecoverySetupMissing,
    /// 5. Everything functional is fine, but no Recovery Key / backup is configured — set up
    ///    the display-once recovery root.
    ///    (`recovery_unconfigured`)
    RecoverySetupReminder,
    /// Nothing to prompt.
    None,
}

/// Boolean inputs sampled from the live app signals each render. Keeping this a
/// plain value type (no `Signal`s) makes the resolver pure and unit-testable.
#[derive(Debug, Clone, Copy, Default)]
pub struct AccountHealthInputs {
    /// A live session + populated account exist (otherwise nothing prompts).
    pub has_session: bool,
    /// First connect + sync finished. Recovery prompts wait for this so they
    /// don't fire against an incomplete account projection.
    pub sync_bootstrap_complete: bool,
    /// The device-authorization probe has returned (so device state is known).
    pub device_check_complete: bool,
    /// User is currently on a recovery/settings-recovery route, where the
    /// recovery reminder would be redundant noise.
    pub on_recovery_route: bool,
    /// User is inside the account-first onboarding flow. That flow owns device
    /// authorization and recovery setup, so global account-health prompts would
    /// duplicate or obscure the active onboarding step.
    pub on_onboarding_route: bool,
    /// Server-side recovery state has been fetched. Backup prompts depend on
    /// this because the UX is different for "use the existing Recovery Key"
    /// versus "create the account Recovery Key".
    pub recovery_check_complete: bool,

    pub needs_device_authorization: bool,
    /// Another active device exists and can actually approve a pairing request.
    /// A first device without a control-stream bootstrap must return to
    /// onboarding; showing the multi-device pairing prompt is a dead end.
    pub account_has_other_devices: bool,
    pub needs_mls_unlock: bool,
    pub needs_mls_backup: bool,
    pub needs_mls_recovery_setup: bool,
    /// No Recovery Key and no recovery backup are configured (SPOF).
    pub recovery_unconfigured: bool,
}

impl AccountHealthInputs {
    /// Resolve the single prompt to show. Convenience wrapper over [`resolve`].
    pub fn resolve(&self) -> AccountHealthPrompt {
        resolve(*self)
    }
}

/// Pure priority resolver. See [`AccountHealthPrompt`] for the ordering.
pub fn resolve(i: AccountHealthInputs) -> AccountHealthPrompt {
    if !i.has_session {
        return AccountHealthPrompt::None;
    }

    // Account-first onboarding is itself the blocking setup surface. In
    // particular, the existing-identity Recovery Key step authorizes the new
    // device, so opening the global pairing prompt on top of it presents two
    // competing ways to complete the same transition.
    if i.on_onboarding_route {
        return AccountHealthPrompt::None;
    }

    // Priority 1: device authorization is the only thing that can run before
    // the device-state probe completes; it must not depend on
    // `sync_bootstrap_complete`. Once known to be needed, it pre-empts all else.
    if i.device_check_complete && i.needs_device_authorization && i.account_has_other_devices {
        return AccountHealthPrompt::DeviceAuthorization;
    }
    // While the device probe is still running, or the device still needs
    // authorization, suppress every downstream prompt: their inputs are not yet
    // trustworthy and the device-auth flow owns the screen.
    if !i.device_check_complete || i.needs_device_authorization {
        return AccountHealthPrompt::None;
    }

    // Priorities 2–3: functional, blocking key-material prompts. These do not
    // wait on `sync_bootstrap_complete` because the boot detection effect sets
    // them directly from the account-secret subscribe payload.
    if i.needs_mls_unlock {
        return AccountHealthPrompt::MlsUnlock;
    }
    if i.needs_mls_backup {
        if !i.recovery_check_complete {
            return AccountHealthPrompt::None;
        }
        return AccountHealthPrompt::MlsBackup;
    }
    // Priority 4: fresh-device dead-end diagnostic (S5). Mutually exclusive with
    // unlock/backup by construction, ordered here for safety.
    if i.needs_mls_recovery_setup {
        return AccountHealthPrompt::RecoverySetupMissing;
    }

    // Priority 5 is advisory. It waits for sync and recovery-state
    // detection, and stays off the recovery routes (where the user is already
    // managing exactly this).
    if !i.sync_bootstrap_complete || i.on_recovery_route || !i.recovery_check_complete {
        return AccountHealthPrompt::None;
    }
    if i.recovery_unconfigured {
        return AccountHealthPrompt::RecoverySetupReminder;
    }
    AccountHealthPrompt::None
}

/// Whether to *proactively* open the 24-word Recovery Key setup modal once.
///
/// True exactly when the resolved prompt is
/// [`AccountHealthPrompt::RecoverySetupReminder`] (account otherwise healthy,
/// synced, device-authorized, recovery state loaded, but no recovery path configured) AND the user
/// has not been auto-prompted before. The caller persists the "prompted" flag so
/// this fires at most once per account — the passive dashboard banner still
/// remains for subsequent sessions. See `docs/user-flows-key-lifecycle.md` §3/S1.
pub fn should_auto_prompt_recovery_setup(i: AccountHealthInputs, already_prompted: bool) -> bool {
    !already_prompted && resolve(i) == AccountHealthPrompt::RecoverySetupReminder
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fully-healthy, signed-in, synced account: no prompt.
    fn healthy() -> AccountHealthInputs {
        AccountHealthInputs {
            has_session: true,
            sync_bootstrap_complete: true,
            device_check_complete: true,
            recovery_check_complete: true,
            ..Default::default()
        }
    }

    #[test]
    fn no_session_never_prompts() {
        let i = AccountHealthInputs {
            has_session: false,
            needs_device_authorization: true,
            needs_mls_unlock: true,
            recovery_unconfigured: true,
            ..Default::default()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::None);
    }

    #[test]
    fn healthy_account_is_silent() {
        assert_eq!(resolve(healthy()), AccountHealthPrompt::None);
    }

    #[test]
    fn device_authorization_preempts_everything() {
        let i = AccountHealthInputs {
            needs_device_authorization: true,
            account_has_other_devices: true,
            needs_mls_unlock: true,
            needs_mls_backup: true,
            needs_mls_recovery_setup: true,
            recovery_unconfigured: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::DeviceAuthorization);
    }

    #[test]
    fn first_device_never_gets_a_multi_device_pairing_prompt() {
        let i = AccountHealthInputs {
            needs_device_authorization: true,
            account_has_other_devices: false,
            ..healthy()
        };

        assert_eq!(resolve(i), AccountHealthPrompt::None);
    }

    #[test]
    fn onboarding_owns_device_authorization_and_recovery_prompts() {
        let i = AccountHealthInputs {
            on_onboarding_route: true,
            needs_device_authorization: true,
            needs_mls_unlock: true,
            needs_mls_backup: true,
            needs_mls_recovery_setup: true,
            recovery_unconfigured: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::None);
    }

    #[test]
    fn nothing_shows_until_device_probe_completes() {
        // Probe not complete: even though several flags are set, we wait — the
        // device-auth decision isn't known yet and downstream inputs are stale.
        let i = AccountHealthInputs {
            device_check_complete: false,
            needs_mls_unlock: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::None);
    }

    #[test]
    fn unlock_beats_backup_and_recovery_states() {
        let i = AccountHealthInputs {
            needs_mls_unlock: true,
            needs_mls_backup: true,
            needs_mls_recovery_setup: true,
            recovery_unconfigured: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::MlsUnlock);
    }

    #[test]
    fn backup_beats_recovery_missing_and_reminder() {
        let i = AccountHealthInputs {
            needs_mls_backup: true,
            needs_mls_recovery_setup: true,
            recovery_unconfigured: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::MlsBackup);
    }

    #[test]
    fn backup_waits_for_recovery_state() {
        let i = AccountHealthInputs {
            needs_mls_backup: true,
            recovery_check_complete: false,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::None);
    }

    #[test]
    fn recovery_missing_beats_reminder() {
        let i = AccountHealthInputs {
            needs_mls_recovery_setup: true,
            recovery_unconfigured: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::RecoverySetupMissing);
    }

    #[test]
    fn recovery_reminder_follows_functional_prompts() {
        let i = AccountHealthInputs {
            recovery_unconfigured: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::RecoverySetupReminder);
    }

    #[test]
    fn advisory_prompts_wait_for_sync() {
        // Unconfigured, but sync not done -> silent (functional prompts already
        // cleared).
        let i = AccountHealthInputs {
            sync_bootstrap_complete: false,
            recovery_unconfigured: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::None);
    }

    #[test]
    fn advisory_prompts_wait_for_recovery_state() {
        let i = AccountHealthInputs {
            recovery_check_complete: false,
            recovery_unconfigured: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::None);
    }

    #[test]
    fn functional_prompts_do_not_wait_for_sync() {
        // unlock must fire even before sync bootstrap completes.
        let i = AccountHealthInputs {
            sync_bootstrap_complete: false,
            needs_mls_unlock: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::MlsUnlock);
    }

    #[test]
    fn advisory_prompts_suppressed_on_recovery_route() {
        let i = AccountHealthInputs {
            on_recovery_route: true,
            recovery_unconfigured: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::None);
    }

    #[test]
    fn recovery_route_does_not_suppress_functional_prompts() {
        let i = AccountHealthInputs {
            on_recovery_route: true,
            needs_mls_backup: true,
            ..healthy()
        };
        assert_eq!(resolve(i), AccountHealthPrompt::MlsBackup);
    }

    #[test]
    fn auto_prompt_fires_once_in_reminder_state() {
        let reminder = AccountHealthInputs {
            recovery_unconfigured: true,
            ..healthy()
        };
        assert_eq!(
            resolve(reminder),
            AccountHealthPrompt::RecoverySetupReminder
        );
        // Not yet prompted -> fire.
        assert!(should_auto_prompt_recovery_setup(reminder, false));
        // Already prompted -> never fire again, even though still unconfigured.
        assert!(!should_auto_prompt_recovery_setup(reminder, true));
    }

    #[test]
    fn auto_prompt_suppressed_outside_reminder_state() {
        // Healthy + configured -> nothing to prompt.
        assert!(!should_auto_prompt_recovery_setup(healthy(), false));
        // Device probe not done -> wait.
        let pending = AccountHealthInputs {
            device_check_complete: false,
            recovery_unconfigured: true,
            ..healthy()
        };
        assert!(!should_auto_prompt_recovery_setup(pending, false));
    }

    /// The derived `Ord` must agree with the documented priority chain.
    #[test]
    fn priority_order_is_monotone() {
        use AccountHealthPrompt::*;
        let order = [
            DeviceAuthorization,
            MlsUnlock,
            MlsBackup,
            RecoverySetupMissing,
            RecoverySetupReminder,
            None,
        ];
        for w in order.windows(2) {
            assert!(w[0] < w[1], "{:?} should outrank {:?}", w[0], w[1]);
        }
    }
}
