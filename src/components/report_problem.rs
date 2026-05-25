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
}
