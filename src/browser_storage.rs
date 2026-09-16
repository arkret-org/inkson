//! Single accessor for the browser `window.localStorage` handle.
//!
//! Every module that persists into `localStorage` (client config, local state
//! root, secure-key-store fallbacks, per-device UI preferences) goes through
//! this one place so the "is there a window / is storage reachable" decision
//! exists exactly once. Desktop builds have no browser storage: the
//! cross-platform helpers below become reads that always miss and writes that
//! are no-ops, and the callers fall back to their on-disk paths.

/// The browser `localStorage` handle, or `None` when this wasm build is not
/// running inside a window (worker, SSR pre-render) or storage is blocked by
/// the user agent.
#[cfg(target_arch = "wasm32")]
pub(crate) fn browser_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|window| window.local_storage().ok().flatten())
}

/// Read one `localStorage` entry. Always `None` on desktop.
#[cfg(target_arch = "wasm32")]
pub(crate) fn local_storage_get(key: &str) -> Option<String> {
    browser_storage()?.get_item(key).ok().flatten()
}

/// See the wasm variant. Desktop has no browser storage.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn local_storage_get(_key: &str) -> Option<String> {
    None
}

/// Write one `localStorage` entry, best effort. A no-op on desktop.
#[cfg(target_arch = "wasm32")]
pub(crate) fn local_storage_set(key: &str, value: &str) {
    if let Some(storage) = browser_storage() {
        let _ = storage.set_item(key, value);
    }
}

/// See the wasm variant. Desktop has no browser storage.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn local_storage_set(_key: &str, _value: &str) {}
