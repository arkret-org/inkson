fn main() {
    if let Err(err) = yougen::event_signer::bootstrap_default_signer("yougen") {
        eprintln!("yougen signer bootstrap failed: {err}");
    }
    // CXP-0007 P3B.8.1 — opt-in Sentry init. The guard must outlive
    // `dioxus::launch` so the Sentry client can drain pending events
    // on shutdown. Without an opt-in or without a build-time
    // SENTRY_DSN, `sentry_init` returns `None` silently — see
    // `telemetry::sentry_init` for the gating rules.
    let prefs = yougen::components::CrashTelemetryPrefs::load_from_env();
    let _sentry_guard = yougen::telemetry::sentry_init(prefs);
    dioxus::launch(yougen::App);
}
