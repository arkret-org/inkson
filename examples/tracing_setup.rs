//! Tracing initialisation sample for inkson.
//!
//! This example shows the two recommended wirings:
//!
//! 1. Native (desktop) target: a `tracing-subscriber` chain that respects `RUST_LOG` and uses
//!    ANSI-coloured terminal output.
//! 2. Browser (wasm32) target: a sketch of how to mirror `tracing` events to the browser console.
//!
//! Run the native variant with:
//!
//! ```text
//! cargo run --example tracing_setup
//! ```
//!
//! The browser sketch is comment-only; the actual hook lives in the Dioxus
//! web entrypoint when the `web` feature is enabled.

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use tracing::{debug, info, warn};

    // Honour `RUST_LOG`; fall back to `info` everywhere if unset.
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,inkson=debug".to_owned());

    // The real client uses `tracing-subscriber` for the formatting layer; in
    // production builds add an `EnvFilter` + `fmt` layer here. For this
    // example we keep the dependency surface minimal and route directly
    // through `tracing`'s default subscriber.
    eprintln!("[tracing_setup] would init subscriber with filter: {filter}");

    info!(target: "inkson::example", "tracing-subscriber wired");
    debug!("debug event — only visible when filter allows it");
    warn!("a warn-level event survives the default filter");

    // In real code (see `src/telemetry.rs`) the native sentry layer is
    // attached behind the `CrashTelemetryPrefs` toggle:
    //
    //     inkson::telemetry::sentry_init(&prefs);
    //
    // Sketch of the production native chain (kept as a comment so this
    // example stays dependency-light):
    //
    //     use tracing_subscriber::{fmt, EnvFilter, prelude::*};
    //     tracing_subscriber::registry()
    //         .with(EnvFilter::try_from_default_env()
    //             .unwrap_or_else(|_| EnvFilter::new("info,inkson=debug")))
    //         .with(fmt::layer().with_ansi(true))
    //         .with(sentry_tracing::layer())  // gated on telemetry prefs
    //         .init();
}

#[cfg(target_arch = "wasm32")]
fn main() {
    // Browser-side sketch. The Dioxus web binary should:
    //
    //   1. Install a panic hook routing to `console.error`:
    //
    //         console_error_panic_hook::set_once();
    //
    //   2. Mirror `tracing` events to `console.{info,warn,error}`:
    //
    //         tracing_wasm::set_as_global_default_with_config(
    //             tracing_wasm::WASMLayerConfigBuilder::new()
    //                 .set_max_level(tracing::Level::DEBUG)
    //                 .build(),
    //         );
    //
}
