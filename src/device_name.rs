//! Friendly device naming.
//!
//! Derives a per-device default `display_name` (so each device gets a
//! meaningful browser-plus-OS name at login instead of a shared
//! constant) and produces a short `device_id` fragment used to tell
//! same-named devices apart in the UI.
//!
//! Spec: `crypto-media/device-lifecycle.md` §4 — `display_name` is the
//! optional, user-facing, mutable device name; the canonical identifier
//! is always `device_id` (`ck:device:<uuidv7>`).

/// Derive a human-readable default device name from the running
/// platform. Used at login / device authorization so each device is
/// distinguishable instead of all sharing one constant name.
pub fn default_device_display_name() -> String {
    platform_device_name()
}

#[cfg(target_arch = "wasm32")]
fn platform_device_name() -> String {
    web_sys::window()
        .and_then(|window| window.navigator().user_agent().ok())
        .map(|ua| name_from_user_agent(&ua))
        .unwrap_or_else(|| "Web browser".to_owned())
}

#[cfg(not(target_arch = "wasm32"))]
fn platform_device_name() -> String {
    let os = match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        "android" => "Android",
        "ios" => "iOS",
        other => other,
    };
    match native_host_label() {
        Some(host) if !host.is_empty() => format!("{host} · {os}"),
        _ => format!("{os} device"),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn native_host_label() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty())
}

/// Build a `<browser>` plus `<os>` label out of a `navigator.userAgent`
/// string. Pure so it is unit-testable on every target.
pub fn name_from_user_agent(ua: &str) -> String {
    match (browser_from_user_agent(ua), os_from_user_agent(ua)) {
        (Some(browser), Some(os)) => format!("{browser} · {os}"),
        (Some(browser), None) => browser.to_owned(),
        (None, Some(os)) => format!("Browser · {os}"),
        (None, None) => "Web browser".to_owned(),
    }
}

/// Token order matters: more specific brand tokens are checked first
/// (e.g. Edge/Opera ship a `Chrome` token; Chrome ships a `Safari`
/// token).
fn browser_from_user_agent(ua: &str) -> Option<&'static str> {
    if ua.contains("Edg") {
        Some("Edge")
    } else if ua.contains("OPR") || ua.contains("Opera") {
        Some("Opera")
    } else if ua.contains("Firefox") || ua.contains("FxiOS") {
        Some("Firefox")
    } else if ua.contains("Chrome") || ua.contains("Chromium") || ua.contains("CriOS") {
        Some("Chrome")
    } else if ua.contains("Safari") {
        Some("Safari")
    } else {
        None
    }
}

/// Token order matters: Android user agents also contain `Linux`, and
/// iOS user agents contain `Mac OS X`, so the more specific tokens are
/// checked first.
fn os_from_user_agent(ua: &str) -> Option<&'static str> {
    if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iPod") {
        Some("iOS")
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("macOS")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    }
}

/// Return a short, stable fragment of a `device_id` for disambiguating
/// devices that share a `display_name`. Uses the tail of the UUID
/// (its random low bits for UUIDv7), keeping the last 6 hex digits.
pub fn device_id_short_suffix(device_id: &str) -> String {
    let tail = device_id.rsplit(':').next().unwrap_or(device_id);
    let cleaned: String = tail
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    let len = cleaned.len();
    if len == 0 {
        return String::new();
    }
    cleaned[len.saturating_sub(6)..].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chrome_on_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
        assert_eq!(name_from_user_agent(ua), "Chrome · Windows");
    }

    #[test]
    fn edge_wins_over_chrome_token() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/124.0 Safari/537.36 Edg/124.0";
        assert_eq!(name_from_user_agent(ua), "Edge · Windows");
    }

    #[test]
    fn firefox_on_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) \
                  Gecko/20100101 Firefox/125.0";
        assert_eq!(name_from_user_agent(ua), "Firefox · macOS");
    }

    #[test]
    fn android_is_not_mislabeled_linux() {
        let ua = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36";
        assert_eq!(name_from_user_agent(ua), "Chrome · Android");
    }

    #[test]
    fn iphone_is_ios_not_macos() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) \
                  AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 \
                  Mobile/15E148 Safari/604.1";
        assert_eq!(name_from_user_agent(ua), "Safari · iOS");
    }

    #[test]
    fn unknown_user_agent_falls_back() {
        assert_eq!(name_from_user_agent("totally-unknown-agent"), "Web browser");
    }

    #[test]
    fn short_suffix_takes_last_six_hex() {
        assert_eq!(
            device_id_short_suffix("ck:device:019640dd-8000-7000-8000-0000000abc12"),
            "0abc12"
        );
    }

    #[test]
    fn short_suffix_handles_plain_and_empty() {
        assert_eq!(device_id_short_suffix("abcdef123456"), "123456");
        assert_eq!(device_id_short_suffix(""), "");
        assert_eq!(device_id_short_suffix("ck:device:"), "");
    }
}
