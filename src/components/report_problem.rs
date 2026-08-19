//! Crash-telemetry opt-in preference (P3B.8).
//!
//! Crash telemetry (Sentry) is opt-in and OFF by default. The boot-time
//! preference feeds [`crate::telemetry::sentry_init`]; the persisted
//! preference lives in `LocalStateStore`.

/// Opt-in preference for crash telemetry. Default is `false` — the
/// user must explicitly tick the box.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CrashTelemetryPrefs {
    pub enabled: bool,
}

impl CrashTelemetryPrefs {
    pub fn is_opt_in(self) -> bool {
        self.enabled
    }

    /// Load the boot-time opt-in preference from the environment.
    ///
    /// The persisted preference lives in `LocalStateStore` and isn't
    /// readable until the Dioxus app tree mounts. For the
    /// `sentry_init` boot call we accept a single env-var override
    /// (`INKSON_CRASH_TELEMETRY_OPT_IN=1`) so deploys / CI can opt
    /// the entire process in without waiting for the persisted
    /// toggle to settle. Returns `default()` (opt-out) on any other
    /// value or when the var is absent.
    pub fn load_from_env() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(value) = std::env::var("INKSON_CRASH_TELEMETRY_OPT_IN") {
                let normalized = value.trim().to_ascii_lowercase();
                let enabled = matches!(normalized.as_str(), "1" | "true" | "on" | "yes");
                return Self { enabled };
            }
        }
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_telemetry_default_is_off() {
        let prefs = CrashTelemetryPrefs::default();
        assert!(!prefs.is_opt_in());
    }

    #[cfg(not(target_arch = "wasm32"))]
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn load_from_env_defaults_to_opt_out() {
        // Serialise env mutation so the two parallel env tests in this
        // module don't race each other when cargo test runs them on
        // separate threads.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        // SAFETY: env vars are process-global; the mutex above scopes
        // mutation to one test at a time within this binary.
        #[allow(
            unsafe_code,
            reason = "the test mutates crash telemetry environment under ENV_LOCK"
        )]
        unsafe {
            std::env::remove_var("INKSON_CRASH_TELEMETRY_OPT_IN");
        }
        let prefs = CrashTelemetryPrefs::load_from_env();
        assert!(!prefs.is_opt_in());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn load_from_env_accepts_truthy_values() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        for value in ["1", "true", "TRUE", "on", "yes"] {
            // SAFETY: env mutation is serialised by ENV_LOCK above.
            #[allow(
                unsafe_code,
                reason = "the test mutates crash telemetry environment under ENV_LOCK"
            )]
            unsafe {
                std::env::set_var("INKSON_CRASH_TELEMETRY_OPT_IN", value);
            }
            let prefs = CrashTelemetryPrefs::load_from_env();
            assert!(prefs.is_opt_in(), "expected opt-in for value {value}");
        }
        // SAFETY: env mutation is serialised by ENV_LOCK above.
        #[allow(
            unsafe_code,
            reason = "the test restores crash telemetry environment under ENV_LOCK"
        )]
        unsafe {
            std::env::remove_var("INKSON_CRASH_TELEMETRY_OPT_IN");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn sentry_init_skips_when_opt_out() {
        let prefs = CrashTelemetryPrefs { enabled: false };
        let guard = crate::telemetry::sentry_init(prefs);
        assert!(guard.is_none());
    }
}
