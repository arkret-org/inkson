use dioxus::prelude::*;

/// App-root signals shared by the session, recovery, and MLS effect groups.
///
/// Keeping this as one custom hook makes their ownership explicit while
/// preserving the original hook registration order in `AppBootstrap`.
pub(super) struct SecurityRuntimeSignals {
    pub(super) mls_key_package_publish_key_seen: Signal<Option<String>>,
    pub(super) mls_welcome_bootstrap_key_seen: Signal<Option<String>>,
    pub(super) mls_admission_reconcile_in_flight: Signal<bool>,
    pub(super) mls_admission_reconcile_pending: Signal<bool>,
    pub(super) mls_admission_diag_last: Signal<String>,
    pub(super) needs_mls_unlock: Signal<bool>,
    pub(super) needs_mls_backup: Signal<bool>,
    pub(super) needs_mls_recovery_setup: Signal<bool>,
    pub(super) needs_device_authorization: Signal<bool>,
    pub(super) device_authorization_check_complete: Signal<bool>,
    pub(super) account_has_other_devices: Signal<bool>,
    pub(super) recovery_key_setup_prompt: Signal<bool>,
    pub(super) encryption_floor_prompt_dismissed: Signal<bool>,
    pub(super) recovery_auto_prompt_fired: Signal<bool>,
    pub(super) account_recovery_configured: Signal<Option<bool>>,
    pub(super) account_recovery_detection_key_seen: Signal<Option<String>>,
    pub(super) account_recovery_retry_attempt: Signal<u8>,
}

/// Declare the security/recovery signal group without changing the ordering or
/// initial values that `AppBootstrap` previously registered inline.
pub(super) fn use_security_runtime_signals() -> SecurityRuntimeSignals {
    let mls_key_package_publish_key_seen = use_signal(|| Option::<String>::None);
    let mls_welcome_bootstrap_key_seen = use_signal(|| Option::<String>::None);
    // Admin-side counterpart of the Welcome bootstrap: serialize admission
    // reconciliation so durable-change and backoff retries cannot overlap.
    let mls_admission_reconcile_in_flight = use_signal(|| false);
    let mls_admission_reconcile_pending = use_signal(|| false);
    // Throttle key for the admission pre-filter diagnostic: only emit a WARN
    // when the (realm, blocking-reason) pair changes, so a genuinely stuck
    // admin gets one visible line per cause.
    let mls_admission_diag_last = use_signal(String::new);
    // Set when this device has no local account secret yet but the server holds
    // an `mls_account_secret` backup; consumed by `MlsUnlockPrompt`.
    let needs_mls_unlock = use_signal(|| false);
    // Set when encryption has been used locally but no account-secret backup is
    // available. Restore always wins, so this is exclusive with unlock.
    let needs_mls_backup = use_signal(|| false);
    // Encrypted history exists, but there is no passphrase-backed account-secret
    // backup this fresh device can unlock.
    let needs_mls_recovery_setup = use_signal(|| false);
    let needs_device_authorization = use_signal(|| false);
    let device_authorization_check_complete = use_signal(|| false);
    let account_has_other_devices = use_signal(|| false);
    let recovery_key_setup_prompt = use_signal(|| false);
    // Session-scoped acknowledgement for recommended-encryption-floor work.
    let encryption_floor_prompt_dismissed = use_signal(|| false);
    // In-memory guard against reopening recovery setup during one session.
    let recovery_auto_prompt_fired = use_signal(|| false);
    let account_recovery_configured = use_signal(|| Option::<bool>::None);
    let account_recovery_detection_key_seen = use_signal(|| Option::<String>::None);
    let account_recovery_retry_attempt = use_signal(|| 0_u8);

    SecurityRuntimeSignals {
        mls_key_package_publish_key_seen,
        mls_welcome_bootstrap_key_seen,
        mls_admission_reconcile_in_flight,
        mls_admission_reconcile_pending,
        mls_admission_diag_last,
        needs_mls_unlock,
        needs_mls_backup,
        needs_mls_recovery_setup,
        needs_device_authorization,
        device_authorization_check_complete,
        account_has_other_devices,
        recovery_key_setup_prompt,
        encryption_floor_prompt_dismissed,
        recovery_auto_prompt_fired,
        account_recovery_configured,
        account_recovery_detection_key_seen,
        account_recovery_retry_attempt,
    }
}
