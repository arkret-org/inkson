#[cfg(not(target_arch = "wasm32"))]
use anyhow::Context;
use url::Url;

/// Launch the authorize URL in the user's browser / webview. On wasm this
/// navigates the current window - the matching `/auth/callback` handler on
/// the same origin reads `?code=` and exchanges it through the SDK session
/// engine. On native desktop builds this best-effort opens the system browser
/// via the platform shell (`cmd /c start`, `xdg-open`, or `open`); production
/// deploys SHOULD swap in a webview crate so the callback URL can be intercepted
/// in-process.
pub fn open_oidc_authorize_url(authorize_url: &str) -> anyhow::Result<()> {
    open_authorize_url_impl(authorize_url)
}

#[cfg(target_arch = "wasm32")]
fn open_authorize_url_impl(authorize_url: &str) -> anyhow::Result<()> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    window
        .location()
        .assign(authorize_url)
        .map_err(|err| anyhow::anyhow!("location.assign failed: {err:?}"))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::needless_return)] // `return` required: target-cfg blocks below are not always present.
fn open_authorize_url_impl(authorize_url: &str) -> anyhow::Result<()> {
    // Validate the URL up front so we never feed an unparsed string to
    // the system shell (defence in depth — the caller should already
    // have validated, but a stray `;` in a hand-edited URL would
    // otherwise compose into a shell injection on Windows `cmd`).
    let parsed = Url::parse(authorize_url)
        .with_context(|| format!("invalid authorize URL: {authorize_url}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("refusing to open non-http(s) authorize URL: {authorize_url}");
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", authorize_url])
            .spawn()
            .with_context(|| "failed to spawn `cmd /C start` for OIDC authorize URL")?;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(authorize_url)
            .spawn()
            .with_context(|| "failed to spawn `open` for OIDC authorize URL")?;
        return Ok(());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(authorize_url)
            .spawn()
            .with_context(|| "failed to spawn `xdg-open` for OIDC authorize URL")?;
        return Ok(());
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", unix)))]
    {
        anyhow::bail!("no browser-open implementation for this target");
    }
}

pub fn extract_authorization_code_from_callback(callback_url: &str) -> anyhow::Result<String> {
    let url = Url::parse(callback_url)?;
    url.query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("callback URL does not contain an authorization code"))
}

pub fn extract_state_from_callback(callback_url: &str) -> anyhow::Result<Option<String>> {
    let url = Url::parse(callback_url)?;
    Ok(url
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned())))
}

pub fn extract_error_from_callback(callback_url: &str) -> anyhow::Result<Option<String>> {
    let url = Url::parse(callback_url)?;
    Ok(url
        .query_pairs()
        .find_map(|(key, value)| (key == "error").then(|| value.into_owned())))
}

pub fn extract_error_description_from_callback(
    callback_url: &str,
) -> anyhow::Result<Option<String>> {
    let url = Url::parse(callback_url)?;
    Ok(url
        .query_pairs()
        .find_map(|(key, value)| (key == "error_description").then(|| value.into_owned())))
}

#[cfg(target_arch = "wasm32")]
pub fn capture_current_browser_callback_url() -> anyhow::Result<String> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let href = window
        .location()
        .href()
        .map_err(|error| anyhow::anyhow!("failed to read browser location: {error:?}"))?;
    callback_url_with_query(&href, browser_initial_navigation_url(&window).as_deref())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn capture_current_browser_callback_url() -> anyhow::Result<String> {
    anyhow::bail!("current browser callback capture is only available in wasm/web builds")
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn callback_url_with_query(
    current_href: &str,
    initial_navigation_href: Option<&str>,
) -> anyhow::Result<String> {
    let current = Url::parse(current_href)?;
    if current.query().is_some() {
        return Ok(current_href.to_owned());
    }

    if let Some(initial_navigation_href) = initial_navigation_href {
        let initial = Url::parse(initial_navigation_href)?;
        if initial.query().is_some() && same_callback_location(&current, &initial) {
            return Ok(initial_navigation_href.to_owned());
        }
    }

    anyhow::bail!("current browser location does not contain callback query parameters")
}

#[cfg(any(target_arch = "wasm32", test))]
fn same_callback_location(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
        && left.path() == right.path()
}

#[cfg(target_arch = "wasm32")]
fn browser_initial_navigation_url(window: &web_sys::Window) -> Option<String> {
    use wasm_bindgen::JsCast as _;

    let performance = js_sys::Reflect::get(window, &"performance".into()).ok()?;
    let get_entries = js_sys::Reflect::get(&performance, &"getEntriesByType".into()).ok()?;
    let get_entries = get_entries.dyn_ref::<js_sys::Function>()?;
    let entries = get_entries.call1(&performance, &"navigation".into()).ok()?;
    let first = js_sys::Array::from(&entries).get(0);
    js_sys::Reflect::get(&first, &"name".into())
        .ok()
        .and_then(|value| value.as_string())
}
