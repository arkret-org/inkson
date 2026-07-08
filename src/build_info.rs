//! Build identity surfaced at runtime for stale-bundle diagnostics.

/// Per-build identifier stamped by `build.rs`:
/// `<local build time> <git short hash>[+dirty]`.
///
/// Printed once at startup ([`crate::App`] entry) so the browser console shows
/// exactly which wasm bundle is loaded. A freshly built bundle carries a newer
/// timestamp than a cached one, so a build id older than your last rebuild means
/// the browser is serving STALE cached wasm (hard-reload or a fresh profile).
pub fn build_id() -> &'static str {
    env!("INKSON_BUILD_ID")
}
