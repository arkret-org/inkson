pub(crate) fn browser_prefers_dark_theme() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|window| {
                window
                    .match_media("(prefers-color-scheme: dark)")
                    .ok()
                    .flatten()
            })
            .map(|query| query.matches())
            .unwrap_or(false)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}

pub(crate) fn browser_shell_color_scheme_is_dark() -> Option<bool> {
    #[cfg(target_arch = "wasm32")]
    {
        let window = web_sys::window()?;
        let document = window.document()?;
        let shell = document
            .query_selector("[data-testid=\"client-shell\"]")
            .ok()
            .flatten()?;
        let styles = window.get_computed_style(&shell).ok().flatten()?;
        let color_scheme = styles
            .get_property_value("color-scheme")
            .ok()?
            .to_ascii_lowercase();
        let has_dark = color_scheme.split_whitespace().any(|token| token == "dark");
        let has_light = color_scheme
            .split_whitespace()
            .any(|token| token == "light");
        if has_dark && !has_light {
            Some(true)
        } else if has_light && !has_dark {
            Some(false)
        } else {
            None
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

pub(crate) fn theme_renders_as_night(theme: &str, system_theme_is_night: bool) -> bool {
    theme == "night" || (theme == "system" && system_theme_is_night)
}

/// Mirror the effective theme onto the document root (`<html>`).
///
/// The vendored dioxus-components theme declares its palette
/// (`--primary-color`, …) on `:root` and flips it with a
/// `var(--light, …) var(--dark, …)` switch keyed on `html[data-theme]`.
/// Those derived custom properties are substituted **once at `:root`**, so
/// toggling `--light`/`--dark` on the shell `<div>` (where inkson renders
/// its `data-theme`) has no effect — descendants inherit the already-computed
/// palette. CSS cannot propagate a `<div>` attribute up to `:root`, so the
/// switch must live on `<html>` itself. Writing `data-theme` here lets the
/// vendored switch — and the `[data-theme]` tokens in
/// `styles/base/tokens.css` — resolve at the level the palette is
/// declared, fixing dxc controls (select, tabs, …) and
/// dialogs teleported under `<body>`. Uses the canonical `light`/`dark`
/// values understood by both the vendored theme and `styles/base/tokens.css`.
pub(crate) fn apply_document_root_theme(is_night: bool) {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(root) = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.document_element())
        {
            let _ = root.set_attribute("data-theme", if is_night { "dark" } else { "light" });
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = is_night;
    }
}

pub(crate) fn next_manual_theme(theme: &str) -> String {
    let is_night = if theme == "system" {
        browser_shell_color_scheme_is_dark().unwrap_or_else(browser_prefers_dark_theme)
    } else {
        theme == "night"
    };
    if is_night { "light" } else { "night" }.to_owned()
}
