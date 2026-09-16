//! Build identity surfaced at runtime for stale-bundle diagnostics.

// `scripts/dev_dioxus.py` rewrites this fixed-content file when a sibling Cargo
// path dependency changes. Keeping it in rustc dep-info makes Dioxus 0.7 classify
// that local event as a full-rebuild input instead of skipping the external file.
const _DEV_DEPENDENCY_REBUILD_STAMP: &str = include_str!("dev_dependency_rebuild.stamp");

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

/// Publish the loaded bundle identity where browser automation and operators
/// can verify it before exercising any product flow.
#[cfg(target_arch = "wasm32")]
pub fn publish_browser_build_identity() -> Result<(), &'static str> {
    let root = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
        .ok_or("browser document root is unavailable")?;
    root.set_attribute("data-inkson-build-id", build_id())
        .map_err(|_| "failed to publish Inkson build id")?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn publish_browser_build_identity() -> Result<(), &'static str> {
    Ok(())
}
