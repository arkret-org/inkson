//! "Report a problem" dialog + crash-telemetry opt-in toggle (P3B.8).
//!
//! The dialog drains the last 5 minutes of `tracing` lines from the
//! [`crate::telemetry`] buffer, attaches the app version + OS, and
//! drops the user into a pre-filled mail-to / GitHub-issue body. The
//! user explicitly clicks "Open report" — we never POST anywhere on
//! the user's behalf.
//!
//! Crash telemetry (Sentry) is opt-in. The toggle lives next to the
//! report button in the settings page; the default is OFF and the
//! preference is persisted via `LocalStateStore`.

use dioxus::prelude::*;

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
    /// (`YOUGEN_CRASH_TELEMETRY_OPT_IN=1`) so deploys / CI can opt
    /// the entire process in without waiting for the persisted
    /// toggle to settle. Returns `default()` (opt-out) on any other
    /// value or when the var is absent.
    pub fn load_from_env() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(value) = std::env::var("YOUGEN_CRASH_TELEMETRY_OPT_IN") {
                let normalized = value.trim().to_ascii_lowercase();
                let enabled = matches!(normalized.as_str(), "1" | "true" | "on" | "yes");
                return Self { enabled };
            }
        }
        Self::default()
    }
}

/// Build the body of the "Report a problem" mail. Caller passes:
/// - `recent_tracing` — last N lines from the `telemetry` buffer.
/// - `app_version` — the `CARGO_PKG_VERSION` constant.
/// - `os` — `std::env::consts::OS` on native, `"web"` on wasm.
pub fn build_report_body(
    recent_tracing: &[String],
    app_version: &str,
    os: &str,
) -> String {
    let mut body = String::new();
    body.push_str("# yougen — problem report\n\n");
    body.push_str("Please describe what you were trying to do above this line.\n\n");
    body.push_str("---\n\n");
    body.push_str(&format!("**App version**: `{app_version}`\n"));
    body.push_str(&format!("**OS**: `{os}`\n\n"));
    body.push_str("## Recent tracing (last 5 minutes)\n\n```text\n");
    if recent_tracing.is_empty() {
        body.push_str("(no recent tracing captured)\n");
    } else {
        for line in recent_tracing {
            body.push_str(line);
            body.push('\n');
        }
    }
    body.push_str("```\n");
    body
}

#[component]
pub fn ReportProblemButton(
    /// Last N tracing lines captured by the telemetry buffer.
    recent_tracing: Vec<String>,
    /// Stable app version (e.g. `env!("CARGO_PKG_VERSION")`).
    app_version: String,
    /// OS label (`macos` / `windows` / `linux` / `web`).
    os: String,
    /// Fires with the rendered body so the parent can copy it to
    /// the clipboard or open a mailto:/issue URL.
    on_open: EventHandler<String>,
) -> Element {
    rsx! {
        button {
            class: "secondary report-problem-button",
            "data-testid": "report-problem-button",
            onclick: move |_| {
                let body = build_report_body(&recent_tracing, &app_version, &os);
                on_open.call(body);
            },
            "Report a problem"
        }
    }
}

#[component]
pub fn CrashTelemetryToggle(
    prefs: CrashTelemetryPrefs,
    on_change: EventHandler<CrashTelemetryPrefs>,
) -> Element {
    let enabled = prefs.enabled;
    rsx! {
        label {
            class: "field crash-telemetry-toggle",
            "data-testid": "crash-telemetry-toggle",
            input {
                r#type: "checkbox",
                checked: enabled,
                "data-testid": "crash-telemetry-checkbox",
                onchange: move |evt| {
                    on_change.call(CrashTelemetryPrefs {
                        enabled: evt.value() == "true" || evt.value() == "on",
                    });
                },
            }
            span { class: "field-label", "Send anonymous crash reports (opt-in)" }
            p { class: "field-help muted",
                "Off by default. When on, yougen sends sanitized crash + panic stack traces via Sentry. Toggle off any time."
            }
        }
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

    #[test]
    fn report_body_includes_version_and_os() {
        let body = build_report_body(&["line one".to_owned()], "0.1.0", "macos");
        assert!(body.contains("0.1.0"));
        assert!(body.contains("macos"));
        assert!(body.contains("line one"));
    }

    #[test]
    fn empty_tracing_renders_placeholder() {
        let body = build_report_body(&[], "0.1.0", "web");
        assert!(body.contains("no recent tracing captured"));
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
        unsafe {
            std::env::remove_var("YOUGEN_CRASH_TELEMETRY_OPT_IN");
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
            unsafe {
                std::env::set_var("YOUGEN_CRASH_TELEMETRY_OPT_IN", value);
            }
            let prefs = CrashTelemetryPrefs::load_from_env();
            assert!(
                prefs.is_opt_in(),
                "expected opt-in for value {value}"
            );
        }
        // SAFETY: env mutation is serialised by ENV_LOCK above.
        unsafe {
            std::env::remove_var("YOUGEN_CRASH_TELEMETRY_OPT_IN");
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
