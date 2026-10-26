//! Platform entry points retain the application until the window closes.
#[cfg(not(target_arch = "wasm32"))]
pub fn asset_directory() -> std::io::Result<std::path::PathBuf> {
    if let Some(directory) = std::env::var_os("INKSON_ASSET_DIR") {
        let directory = std::path::PathBuf::from(directory);
        if directory.is_absolute() {
            return Ok(directory);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "INKSON_ASSET_DIR must be absolute",
        ));
    }
    let executable = std::env::current_exe()?;
    let parent = executable.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "executable directory is unavailable",
        )
    })?;
    let adjacent = parent.join("assets");
    if adjacent.is_dir() {
        return Ok(adjacent);
    }
    #[cfg(target_os = "macos")]
    if parent.file_name().is_some_and(|name| name == "MacOS") {
        return Ok(parent.join("../Resources/assets"));
    }
    #[cfg(target_os = "linux")]
    if parent.file_name().is_some_and(|name| name == "bin") {
        return Ok(parent.join("../share/inkson/assets"));
    }
    Ok(adjacent)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn asset_url(relative: &str) -> anyhow::Result<String> {
    use std::path::Component;
    let relative = std::path::Path::new(relative);
    anyhow::ensure!(
        relative
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
        "asset paths must stay inside the assets directory"
    );
    let relative = relative.to_string_lossy().replace('\\', "/");
    Ok(url::Url::parse("asset://inkson/")?
        .join(&relative)?
        .to_string())
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn prioritize_browser_styles() -> std::result::Result<(), wasm_bindgen::JsValue> {
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| wasm_bindgen::JsValue::from_str("Browser document is unavailable"))?;
    let head = document
        .query_selector("head")?
        .ok_or_else(|| wasm_bindgen::JsValue::from_str("Browser document head is unavailable"))?;
    let stylesheets = ["inkson-sapid-css", "inkson-app-css"]
        .into_iter()
        .filter_map(|id| document.get_element_by_id(id))
        .filter(|element| {
            element.tag_name().eq_ignore_ascii_case("link")
                && element.get_attribute("rel").as_deref() == Some("stylesheet")
                && element
                    .parent_node()
                    .is_some_and(|parent| parent.is_same_node(Some(head.as_ref())))
        })
        .collect::<Vec<_>>();
    let Some(first) = stylesheets.first() else {
        return Ok(());
    };
    if let Some(baseline) = head.query_selector("style[data-gly-base=\"v1\"]")?
        && baseline
            .parent_node()
            .is_some_and(|parent| parent.is_same_node(Some(head.as_ref())))
        && baseline.text_content().as_deref() == Some(glory::html::BASE_CSS)
    {
        // The public adapter reset is inline. Moving it preserves both loaded
        // author CSSStyleSheets; moving their link nodes would reload them.
        head.insert_before(&baseline, Some(first.as_ref()))?;
        return Ok(());
    }
    tracing::warn!(
        "Glory inline baseline is unavailable or changed after launch; reprioritizing application stylesheet links may revalidate cached CSS"
    );
    for stylesheet in stylesheets {
        head.append_child(&stylesheet)?;
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::cell::RefCell;

    use wasm_bindgen::prelude::*;

    thread_local! {
        static APP: RefCell<Option<glory::web::WebApp>> = const { RefCell::new(None) };
    }

    #[wasm_bindgen(start)]
    pub fn start() -> Result<(), JsValue> {
        #[cfg(feature = "spec-conformance")]
        if web_sys::window()
            .and_then(|window| window.location().search().ok())
            .is_some_and(|search| {
                url::form_urlencoded::parse(search.trim_start_matches('?').as_bytes())
                    .find(|(name, _)| name == "__inkson_fixture")
                    .is_some_and(|(_, value)| {
                        matches!(value.as_ref(), "message-menu" | "attachment-lifetime")
                    })
            })
        {
            return Ok(());
        }
        let mut tracing = tracing_wasm::WASMLayerConfigBuilder::new();
        tracing
            .set_max_level(tracing::Level::WARN)
            .set_report_logs_in_timings(false);
        tracing_wasm::set_as_global_default_with_config(tracing.build());
        crate::build_info::publish_browser_build_identity().map_err(JsValue::from_str)?;
        let root = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.get_element_by_id("app"))
            .ok_or_else(|| JsValue::from_str("Inkson application root is missing"))?;
        let app = glory::web::launch_with(root, crate::app::root)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        super::prioritize_browser_styles()?;
        APP.with(|slot| *slot.borrow_mut() = Some(app));
        Ok(())
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
pub fn run_native() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use glory::blitz::assets::{LoadConfig, Loader, Url};
    use glory::blitz::shell::{Shell, WindowApp, WindowAttributes};
    use glory::ui::Widget;

    let loader = Arc::new(Loader::new(LoadConfig {
        mounts: BTreeMap::from([("inkson".to_owned(), asset_directory()?.canonicalize()?)]),
        ..Default::default()
    })?);
    let images =
        super::native_images::ScopedImageRegistry::new(super::native_images::Limits::default())?;
    let provider = Arc::new(super::native_images::CompositeProvider {
        images: images.clone(),
        assets: loader,
    });
    let window = WindowApp::with_config(glory::blitz::Config {
        base_url: Url::parse("asset://inkson/")?,
        provider: Some(provider),
        ..Default::default()
    });
    window
        .renderer()
        .set_css(include_str!(concat!(env!("OUT_DIR"), "/inkson.css")));
    let root_images = images.clone();
    window.mount_with(|| {
        glory::prelude::widget(move |scope| {
            crate::app::native_root(scope, root_images.clone()).build(scope)
        })
    })?;
    let mut shell = Shell::new()?;
    shell.add_window(window, WindowAttributes::default().with_title("Inkson"));
    shell.run()?;
    if let Ok(stats) = images.stats() {
        tracing::debug!(
            entries = stats.entries,
            bytes = stats.bytes,
            pending = stats.pending,
            owners = stats.owners,
            peak_pending = stats.peak_pending,
            completed = stats.completed,
            failed = stats.failed,
            cancelled = stats.cancelled,
            rejected = stats.rejected,
            closed = stats.closed,
            stopped = stats.stopped,
            "native image window stopped"
        );
    }
    Ok(())
}
