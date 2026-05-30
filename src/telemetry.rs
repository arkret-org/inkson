//! Client-side telemetry mirroring sodmin's `utils/audit.rs` shape.
//!
//! Why this exists: yougen needs a structured "what action did the
//! user just take" trace matching the operator console (sodmin). This
//! module gives every interactive surface (settings page, device-revoke,
//! OIDC refresh, MLS commit, push subscribe) a single typed call site:
//!
//! ```ignore
//! use yougen::telemetry::{emit_user_action_log, UserActionOutcome};
//!
//! emit_user_action_log(
//!     &mut store,
//!     "did:key:zAlice",
//!     "oidc.refresh",
//!     UserActionOutcome::Success,
//!     None,
//! );
//! ```
//!
//! The default implementation buffers entries into
//! `LocalStateStore::telemetry_log` (bounded at
//! `TELEMETRY_BUFFER_CAP`). A separate flush path (future round) drains
//! the buffer and ships entries to soland's `cx.audit.user_action`
//! endpoint. Until then the buffer is durable, ordered, and survives a
//! browser refresh / desktop restart because it rides on the same
//! `state.json` / `localStorage` channel as the rest of the local state.
//!
//! Schema mirrors sodmin's `format_admin_audit_line` so the operator
//! console can ingest yougen-emitted entries without schema work:
//! `actor` / `action` / `outcome` plus an optional `note`. The
//! line-formatting helper [`format_user_action_line`] produces the
//! exact same wire shape sodmin's grep tooling already understands.

use chrono::Utc;
use tracing::info;

use crate::local_state::{LocalStateStore, UserActionLogEntry};

/// CXP-0007 P3B.8.1 — initialise the opt-in Sentry client.
///
/// The init is gated on TWO conditions:
///   1. `prefs.enabled == true` — the user explicitly opted in via
///      [`crate::components::CrashTelemetryToggle`]. Off by default.
///   2. The build-time `SENTRY_DSN` env var is non-empty. When unset, we log a debug breadcrumb and
///      return `None` silently — never panic. This makes the function safe to call unconditionally
///      from `main` / `App::default` without leaking a guard into every test binary.
///
/// On wasm builds Sentry is not compiled in (the `sentry` crate
/// pulls in `tokio` features that don't apply to the browser); the
/// function returns `None` after a debug breadcrumb so the wasm
/// build still satisfies the type-check.
///
/// Returns the [`sentry::ClientInitGuard`] which the caller MUST keep
/// alive for the duration of the program; dropping it ends the
/// Sentry session.
#[cfg(not(target_arch = "wasm32"))]
pub fn sentry_init(
    prefs: crate::components::CrashTelemetryPrefs,
) -> Option<sentry::ClientInitGuard> {
    if !prefs.is_opt_in() {
        tracing::debug!("sentry_init: skipped — crash telemetry opt-in is off");
        return None;
    }
    let dsn = option_env!("SENTRY_DSN")
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(dsn) = dsn else {
        tracing::debug!("sentry_init: skipped — SENTRY_DSN env var was empty at build time");
        return None;
    };
    let dsn = match dsn.parse::<sentry::types::Dsn>() {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::debug!("sentry_init: skipped — DSN failed to parse: {err}");
            return None;
        }
    };
    let options = sentry::ClientOptions {
        dsn: Some(dsn),
        attach_stacktrace: true,
        release: sentry::release_name!(),
        ..Default::default()
    };
    let guard = sentry::init(options);
    tracing::info!("sentry_init: crash telemetry active");
    Some(guard)
}

/// Wasm stub — Sentry is not compiled into the browser build. Logs a
/// debug breadcrumb and returns `None` so call sites can treat the
/// init uniformly across targets.
#[cfg(target_arch = "wasm32")]
pub fn sentry_init(_prefs: crate::components::CrashTelemetryPrefs) -> Option<()> {
    tracing::debug!("sentry_init: skipped — wasm builds do not link Sentry");
    None
}

/// Outcome of a user action — mirrors sodmin's `AdminAuditOutcome`
/// surface (the wire labels match exactly so a downstream parser can
/// merge sodmin admin and yougen client audit streams without
/// translation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserActionOutcome {
    /// The action completed and the server (or local handler) accepted
    /// it. For local-only actions (e.g. drafting a message) this is
    /// the only success outcome.
    Success,
    /// The action was rejected by a server response or a local
    /// validation step.
    Rejected,
    /// The action could not be executed because the underlying surface
    /// is not yet wired (404 from the server, or a feature flag
    /// disabling the path).
    NotWired,
    /// The action was started but failed mid-flight (network drop,
    /// crypto error, signing key unavailable). Distinct from
    /// `Rejected` so the operator console can tell apart "server said
    /// no" vs "we couldn't even ask".
    Failed,
}

impl UserActionOutcome {
    /// Stable wire label. Matches sodmin's labels (`accepted` /
    /// `rejected` / `not_wired`) plus `failed` for the local-failure
    /// case.
    pub fn label(&self) -> &'static str {
        match self {
            UserActionOutcome::Success => "accepted",
            UserActionOutcome::Rejected => "rejected",
            UserActionOutcome::NotWired => "not_wired",
            UserActionOutcome::Failed => "failed",
        }
    }

    /// Map an HTTP status code to an outcome. `2xx` → `Success`,
    /// `404` → `NotWired`, anything else → `Rejected`.
    pub fn from_http_status(status: u16) -> Self {
        match status {
            200..=299 => UserActionOutcome::Success,
            404 => UserActionOutcome::NotWired,
            _ => UserActionOutcome::Rejected,
        }
    }
}

/// Maximum length (in chars) of a sanitised note before truncation.
/// Matches sodmin's audit clamp so the two streams produce
/// identically-shaped lines.
pub const NOTE_MAX_CHARS: usize = 120;

/// Strip newlines / tabs and clamp to [`NOTE_MAX_CHARS`]. Mirrors
/// sodmin's `redact_note`. Pure helper so the unit tests can pin the
/// exact wire shape.
fn redact_note(note: &str) -> String {
    let cleaned: String = note
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            _ => c,
        })
        .collect();
    if cleaned.chars().count() <= NOTE_MAX_CHARS {
        cleaned
    } else {
        let truncated: String = cleaned.chars().take(NOTE_MAX_CHARS - 3).collect();
        format!("{truncated}...")
    }
}

/// Format a user-action log line. Pure helper — exposed so external
/// log sinks can re-render the same shape without going through
/// `tracing`. Mirrors sodmin's `format_admin_audit_line` byte-for-byte
/// with `yougen.user.action` as the prefix.
pub fn format_user_action_line(
    actor: &str,
    action: &str,
    outcome: UserActionOutcome,
    note: Option<&str>,
) -> String {
    let note_part = match note.map(str::trim).filter(|s| !s.is_empty()) {
        Some(n) => format!(" note={}", redact_note(n)),
        None => String::new(),
    };
    format!(
        "yougen.user.action actor={} action={} outcome={}{}",
        actor,
        action,
        outcome.label(),
        note_part,
    )
}

/// Build a `UserActionLogEntry` ready to be appended to the local
/// state buffer. Splits the construction from `emit_user_action_log`
/// so the (rare) caller that wants to batch multiple entries can call
/// `append_telemetry` directly.
pub fn build_user_action_entry(
    actor: &str,
    action: &str,
    outcome: UserActionOutcome,
    note: Option<&str>,
) -> UserActionLogEntry {
    UserActionLogEntry {
        actor: actor.to_owned(),
        action: action.to_owned(),
        outcome: outcome.label().to_owned(),
        note: note
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(redact_note),
        recorded_at: Utc::now(),
    }
}

/// Default emit path — both logs the action via `tracing` (so the
/// developer console / dioxus-logger sink picks it up immediately) and
/// appends a structured entry to the persisted buffer (so it survives
/// offline → online transitions and ships on the next flush).
///
/// Call sites typically pass `&mut store` from the dioxus context;
/// when that's awkward (background task with a snapshot), use
/// [`build_user_action_entry`] + `LocalStateStore::append_telemetry`.
pub fn emit_user_action_log(
    store: &mut LocalStateStore,
    actor: &str,
    action: &str,
    outcome: UserActionOutcome,
    note: Option<&str>,
) {
    info!("{}", format_user_action_line(actor, action, outcome, note));
    let entry = build_user_action_entry(actor, action, outcome, note);
    store.append_telemetry(entry);
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_arch = "wasm32"))]
    use std::path::PathBuf;
    #[cfg(not(target_arch = "wasm32"))]
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    fn isolated_store(tag: &str) -> LocalStateStore {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path: PathBuf =
            std::env::temp_dir().join(format!("yougen-telemetry-{tag}-{stamp}.json"));
        LocalStateStore::with_path(path)
    }

    #[test]
    fn outcome_labels_match_sodmin_wire_shape() {
        assert_eq!(UserActionOutcome::Success.label(), "accepted");
        assert_eq!(UserActionOutcome::Rejected.label(), "rejected");
        assert_eq!(UserActionOutcome::NotWired.label(), "not_wired");
        assert_eq!(UserActionOutcome::Failed.label(), "failed");
    }

    #[test]
    fn http_status_to_outcome_classifies_404_as_not_wired() {
        assert_eq!(
            UserActionOutcome::from_http_status(200),
            UserActionOutcome::Success
        );
        assert_eq!(
            UserActionOutcome::from_http_status(204),
            UserActionOutcome::Success
        );
        assert_eq!(
            UserActionOutcome::from_http_status(404),
            UserActionOutcome::NotWired
        );
        assert_eq!(
            UserActionOutcome::from_http_status(500),
            UserActionOutcome::Rejected
        );
        assert_eq!(
            UserActionOutcome::from_http_status(401),
            UserActionOutcome::Rejected
        );
    }

    #[test]
    fn format_user_action_line_is_grep_friendly_single_line() {
        let line = format_user_action_line(
            "did:key:zAlice",
            "oidc.refresh",
            UserActionOutcome::Success,
            None,
        );
        assert!(line.starts_with("yougen.user.action"));
        assert!(line.contains("actor=did:key:zAlice"));
        assert!(line.contains("action=oidc.refresh"));
        assert!(line.contains("outcome=accepted"));
        assert!(!line.contains("note="));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn format_user_action_line_includes_note_when_present() {
        let line = format_user_action_line(
            "did:anon",
            "device.revoke",
            UserActionOutcome::Failed,
            Some("network unreachable"),
        );
        assert!(line.contains("note=network unreachable"));
        assert!(line.contains("outcome=failed"));
    }

    #[test]
    fn format_user_action_line_drops_blank_note() {
        let line = format_user_action_line(
            "did:anon",
            "device.revoke",
            UserActionOutcome::Failed,
            Some("   "),
        );
        assert!(!line.contains("note="));
    }

    #[test]
    fn redact_note_strips_newlines_and_clamps() {
        let messy = "line1\nline2\rline3\ttab";
        let clean = redact_note(messy);
        assert!(!clean.contains('\n'));
        assert!(!clean.contains('\r'));
        assert!(!clean.contains('\t'));
        assert!(clean.contains("line1 line2 line3 tab"));

        let long = "x".repeat(500);
        let clamped = redact_note(&long);
        assert_eq!(clamped.chars().count(), NOTE_MAX_CHARS);
        assert!(clamped.ends_with("..."));
    }

    #[test]
    fn build_user_action_entry_strips_blank_note() {
        let entry = build_user_action_entry(
            "did:anon",
            "draft.save",
            UserActionOutcome::Success,
            Some("   "),
        );
        assert!(entry.note.is_none());
        assert_eq!(entry.outcome, "accepted");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn emit_user_action_log_persists_into_store_buffer() {
        let mut store = isolated_store("emit-persists");
        emit_user_action_log(
            &mut store,
            "did:key:zAlice",
            "oidc.refresh",
            UserActionOutcome::Success,
            Some("bg-poll"),
        );
        let log = store.telemetry_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].actor, "did:key:zAlice");
        assert_eq!(log[0].action, "oidc.refresh");
        assert_eq!(log[0].outcome, "accepted");
        assert_eq!(log[0].note.as_deref(), Some("bg-poll"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn drain_telemetry_returns_and_clears_buffer() {
        let mut store = isolated_store("drain-clears");
        emit_user_action_log(
            &mut store,
            "did:anon",
            "settings.theme.set",
            UserActionOutcome::Success,
            None,
        );
        emit_user_action_log(
            &mut store,
            "did:anon",
            "push.subscribe",
            UserActionOutcome::Failed,
            Some("permission denied"),
        );
        let drained = store.drain_telemetry();
        assert_eq!(drained.len(), 2);
        assert!(store.telemetry_log().is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn telemetry_buffer_caps_at_telemetry_buffer_cap() {
        use crate::local_state::TELEMETRY_BUFFER_CAP;
        let mut store = isolated_store("buffer-cap");
        for i in 0..(TELEMETRY_BUFFER_CAP + 50) {
            emit_user_action_log(
                &mut store,
                "did:anon",
                &format!("draft.save.{i}"),
                UserActionOutcome::Success,
                None,
            );
        }
        let log = store.telemetry_log();
        assert_eq!(log.len(), TELEMETRY_BUFFER_CAP);
        // The oldest 50 entries were dropped; the first survivor is
        // entry index 50.
        assert_eq!(log[0].action, "draft.save.50");
        assert_eq!(
            log.last().unwrap().action,
            format!("draft.save.{}", TELEMETRY_BUFFER_CAP + 49)
        );
    }
}
