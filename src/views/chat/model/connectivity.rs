/// Read `navigator.onLine`. Defaults to `true` off-wasm and when the
/// navigator is unavailable so non-browser builds never block sends.
pub(crate) fn navigator_online() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .map(|window| window.navigator().on_line())
            .unwrap_or(true)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        true
    }
}
