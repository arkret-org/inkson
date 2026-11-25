#![cfg_attr(
    all(target_os = "windows", feature = "desktop", not(debug_assertions)),
    windows_subsystem = "windows"
)]

#[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "--inkson-media-host")
    {
        return inkson::rtc_transport::native_host::run();
    }
    #[cfg(target_os = "windows")]
    if std::env::var_os("WGPU_BACKEND").is_none() {
        // Some Windows Vulkan drivers crash while wgpu enumerates adapters.
        // SAFETY: set_var is safe on Windows. Set the default before the renderer starts.
        #[allow(
            unsafe_code,
            reason = "Windows-only process environment initialization"
        )]
        unsafe {
            std::env::set_var("WGPU_BACKEND", "dx12");
        }
    }
    use tracing_subscriber::prelude::*;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("inkson=info,warn"));
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer());
    let _ = tracing::subscriber::set_global_default(subscriber);
    tracing::warn!(target: "build", build_id = inkson::build_info::build_id(), "inkson build loaded");
    let prefs = inkson::components::CrashTelemetryPrefs::load_from_env();
    let _sentry = inkson::telemetry::sentry_init(prefs);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _runtime = runtime.enter();
    inkson::presentation::host::run_native()
}

#[cfg(any(target_arch = "wasm32", not(feature = "desktop")))]
fn main() {}
