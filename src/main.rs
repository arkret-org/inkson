fn main() {
    init_tracing();
    if let Err(error) = inkson::build_info::publish_browser_build_identity() {
        panic!("build identity publication failed: {error}");
    }
    // First console line: which wasm bundle the browser actually loaded. If this
    // id is older than your last rebuild, the browser is running STALE cached
    // wasm — hard-reload or use a fresh profile. (Stamped by `build.rs`.)
    tracing::warn!(
        target: "build",
        build_id = inkson::build_info::build_id(),
        "inkson build loaded"
    );
    // P3B.8.1 — opt-in Sentry init. The guard must outlive
    // `dioxus::launch` so the Sentry client can drain pending events
    // on shutdown. Without an opt-in or without a build-time
    // SENTRY_DSN, `sentry_init` returns `None` silently — see
    // `telemetry::sentry_init` for the gating rules.
    let prefs = inkson::components::CrashTelemetryPrefs::load_from_env();
    let _sentry_guard = inkson::telemetry::sentry_init(prefs);
    dioxus::launch(inkson::App);
}

#[cfg(not(target_arch = "wasm32"))]
fn init_tracing() {
    use tracing_subscriber::prelude::*;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("inkson=info,warn"));
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer());
    let _ = tracing::subscriber::set_global_default(subscriber);
}

#[cfg(target_arch = "wasm32")]
fn init_tracing() {
    let mut builder = tracing_wasm::WASMLayerConfigBuilder::new();
    builder
        .set_max_level(tracing::Level::WARN)
        .set_report_logs_in_timings(false);
    tracing_wasm::set_as_global_default_with_config(builder.build());
}
