fn main() {
    init_tracing();
    if let Err(err) = yougen::event_signer::bootstrap_default_signer("yougen") {
        eprintln!("yougen signer bootstrap failed: {err}");
    }
    // CKP-0007 P3B.8.1 — opt-in Sentry init. The guard must outlive
    // `dioxus::launch` so the Sentry client can drain pending events
    // on shutdown. Without an opt-in or without a build-time
    // SENTRY_DSN, `sentry_init` returns `None` silently — see
    // `telemetry::sentry_init` for the gating rules.
    let prefs = yougen::components::CrashTelemetryPrefs::load_from_env();
    let _sentry_guard = yougen::telemetry::sentry_init(prefs);
    dioxus::launch(yougen::App);
}

#[cfg(not(target_arch = "wasm32"))]
fn init_tracing() {
    use tracing_subscriber::prelude::*;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("yougen=info,warn"));
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer());
    let _ = tracing::subscriber::set_global_default(subscriber);
}

#[cfg(target_arch = "wasm32")]
fn init_tracing() {
    tracing_wasm::set_as_global_default();
}
