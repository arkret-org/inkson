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

pub(crate) fn stored_theme_preference(store: &crate::state::LocalStateStore) -> String {
    crate::components::ThemeMode::from_persisted_str(
        store
            .load_plain_local_data("theme")
            .as_deref()
            .unwrap_or_default(),
    )
    .as_persisted_str()
    .to_owned()
}

pub(crate) fn theme_renders_as_night(theme: &str, system_theme_is_night: bool) -> bool {
    use crate::components::ThemeMode;

    match ThemeMode::from_persisted_str(theme) {
        ThemeMode::Light => false,
        ThemeMode::Dark => true,
        ThemeMode::System => system_theme_is_night,
    }
}

/// Mirror the effective theme onto the document root for inherited custom properties.
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
