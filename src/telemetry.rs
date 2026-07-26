//! Opt-in crash telemetry initialisation.

/// AKP-0007 P3B.8.1 — initialise the opt-in Sentry client.
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
        // R18: never let the SDK attach default PII (IP address, request
        // headers, usernames). Crash telemetry is opt-in but MUST stay
        // privacy-preserving by default.
        send_default_pii: false,
        // R18: capture every error event (explicit rather than relying on the
        // SDK default) while leaving performance tracing off — inkson does not
        // emit transactions, so traces are not sampled.
        sample_rate: 1.0,
        traces_sample_rate: 0.0,
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
