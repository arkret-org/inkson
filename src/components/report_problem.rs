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
use dioxus_primitives::checkbox::CheckboxState;

use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;

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

/// Build the body of the "Report a problem" mail. Caller passes:
/// - `recent_tracing` — last N lines from the `telemetry` buffer.
/// - `app_version` — the `CARGO_PKG_VERSION` constant.
/// - `os` — `std::env::consts::OS` on native, `"web"` on wasm.
pub fn build_report_body(recent_tracing: &[String], app_version: &str, os: &str) -> String {
    let mut body = String::new();
    body.push_str("# inkson — problem report\n\n");
    body.push_str("Please describe what you were trying to do above this line.\n\n");
    body.push_str("---\n\n");
    body.push_str(&format!("**App version**: `{app_version}`\n"));
    body.push_str(&format!("**OS**: `{os}`\n\n"));
    body.push_str("## Recent tracing (last 5 minutes)\n\n```text\n");
    if recent_tracing.is_empty() {
        body.push_str("(no recent tracing captured)\n");
    } else {
        for line in recent_tracing {
            body.push_str(&sanitize_report_trace_line(line));
            body.push('\n');
        }
    }
    body.push_str("```\n");
    body
}

fn sanitize_report_trace_line(line: &str) -> String {
    let prefix_redacted = redact_prefixed_identifiers(line);
    prefix_redacted
        .split_inclusive(char::is_whitespace)
        .map(redact_handle_like_segment)
        .collect()
}

fn redact_prefixed_identifiers(line: &str) -> String {
    let mut redacted = String::with_capacity(line.len());
    let mut index = 0;
    while index < line.len() {
        let rest = &line[index..];
        let replacement = if rest.starts_with("did:") {
            Some("<redacted:did>")
        } else if rest.starts_with("ck:") {
            Some("<redacted:cokret-id>")
        } else if rest.starts_with("acct:") {
            Some("<redacted:handle>")
        } else if rest.starts_with("web+cokret:") {
            Some("<redacted:cokret-link>")
        } else {
            None
        };

        if let Some(marker) = replacement {
            redacted.push_str(marker);
            index = advance_sensitive_token(line, index);
            continue;
        }

        let Some(ch) = rest.chars().next() else {
            break;
        };
        redacted.push(ch);
        index += ch.len_utf8();
    }
    redacted
}

fn advance_sensitive_token(line: &str, start: usize) -> usize {
    let mut index = start;
    while index < line.len() {
        let Some(ch) = line[index..].chars().next() else {
            break;
        };
        if ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | '`' | '<' | '>' | '[' | ']' | '{' | '}' | '(' | ')' | ',' | ';'
            )
        {
            break;
        }
        index += ch.len_utf8();
    }
    index
}

fn redact_handle_like_segment(segment: &str) -> String {
    let trimmed = segment.trim_matches(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | '`' | '<' | '>' | '[' | ']' | '{' | '}' | '(' | ')' | ',' | ';'
            )
    });
    if trimmed.contains('@') && looks_like_user_handle(trimmed) {
        segment.replace(trimmed, "<redacted:handle>")
    } else {
        segment.to_owned()
    }
}

fn looks_like_user_handle(token: &str) -> bool {
    if token.starts_with('@') {
        return token.len() > 1;
    }
    token
        .split_once('@')
        .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
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
        Button {
            variant: ButtonVariant::Secondary,
            class: "report-problem-button",
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
            Checkbox {
                checked: if enabled { CheckboxState::Checked } else { CheckboxState::Unchecked },
                "data-testid": "crash-telemetry-checkbox",
                on_checked_change: move |state: CheckboxState| {
                    let enabled = bool::from(state);
                    on_change.call(CrashTelemetryPrefs { enabled });
                },
            }
            span { class: "field-label", "Send anonymous crash reports (opt-in)" }
            p { class: "field-help muted",
                "Off by default. When on, inkson sends sanitized crash + panic stack traces via Sentry. Toggle off any time."
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

    #[test]
    fn report_body_redacts_stable_identifiers_from_tracing() {
        let body = build_report_body(
            &[
                "actor=did:web:alice.example realm=ck:realm:01964137-0000-7000-8000-000000000001"
                    .to_owned(),
                "handle alice@example.com opened web+cokret:realm/demo".to_owned(),
            ],
            "0.1.0",
            "web",
        );

        assert!(body.contains("<redacted:did>"));
        assert!(body.contains("<redacted:cokret-id>"));
        assert!(body.contains("<redacted:handle>"));
        assert!(body.contains("<redacted:cokret-link>"));
        assert!(!body.contains("did:web:alice.example"));
        assert!(!body.contains("alice@example.com"));
        assert!(!body.contains("ck:realm:01964137"));
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
            unsafe {
                std::env::set_var("INKSON_CRASH_TELEMETRY_OPT_IN", value);
            }
            let prefs = CrashTelemetryPrefs::load_from_env();
            assert!(prefs.is_opt_in(), "expected opt-in for value {value}");
        }
        // SAFETY: env mutation is serialised by ENV_LOCK above.
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
