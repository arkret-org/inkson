//! Application host services that are outside the portable widget contract.
#[cfg(target_arch = "wasm32")]
pub async fn copy_text(value: &str) -> Result<(), String> {
    let window = web_sys::window().ok_or("Browser window unavailable")?;
    wasm_bindgen_futures::JsFuture::from(window.navigator().clipboard().write_text(value))
        .await
        .map(|_| ())
        .map_err(|error| format!("Clipboard failed: {error:?}"))
}
#[cfg(not(target_arch = "wasm32"))]
thread_local! {static CLIPBOARD:std::cell::RefCell<Option<arboard::Clipboard>>=const{std::cell::RefCell::new(None)};}
#[cfg(not(target_arch = "wasm32"))]
fn write_native_clipboard(value: &str) -> Result<(), String> {
    CLIPBOARD.with(|clipboard| {
        let mut clipboard = clipboard.borrow_mut();
        if clipboard.is_none() {
            *clipboard = Some(arboard::Clipboard::new().map_err(|error| error.to_string())?);
        }
        clipboard
            .as_mut()
            .ok_or_else(|| "OS clipboard is unavailable".to_owned())?
            .set_text(value)
            .map_err(|error| error.to_string())
    })
}
#[cfg(not(target_arch = "wasm32"))]
pub async fn copy_text(value: &str) -> Result<(), String> {
    write_native_clipboard(value)
}
pub fn copy_text_to_clipboard(value: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        let value = value.to_owned();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(error) = copy_text(&value).await {
                tracing::warn!(%error,"clipboard write failed");
            }
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        if let Err(error) = write_native_clipboard(value) {
            tracing::warn!(%error,"clipboard write failed");
        }
    }
}
#[cfg(target_arch = "wasm32")]
pub fn download_text_as_file(filename: &str, value: &str) {
    use wasm_bindgen::JsCast;
    let result = (|| -> Result<(), wasm_bindgen::JsValue> {
        let window = web_sys::window()
            .ok_or_else(|| wasm_bindgen::JsValue::from_str("Browser window unavailable"))?;
        let document = window
            .document()
            .ok_or_else(|| wasm_bindgen::JsValue::from_str("Browser document unavailable"))?;
        let parts = js_sys::Array::new();
        parts.push(&wasm_bindgen::JsValue::from_str(value));
        let options = web_sys::BlobPropertyBag::new();
        options.set_type("text/plain;charset=utf-8");
        let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &options)?;
        let url = web_sys::Url::create_object_url_with_blob(&blob)?;
        let anchor = document
            .create_element("a")?
            .dyn_into::<web_sys::HtmlAnchorElement>()?;
        anchor.set_href(&url);
        anchor.set_download(filename);
        if let Some(body) = document.body() {
            body.append_child(&anchor)?;
            anchor.click();
            anchor.remove();
        }
        let revoke = url.clone();
        let callback = wasm_bindgen::closure::Closure::once_into_js(move || {
            let _ = web_sys::Url::revoke_object_url(&revoke);
        });
        window.set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.unchecked_ref(),
            1000,
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        tracing::warn!(?error, "download failed");
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub fn download_text_as_file(filename: &str, value: &str) {
    if let Some(path) = rfd::FileDialog::new()
        .set_file_name(filename)
        .add_filter("Text", &["txt"])
        .save_file()
        && let Err(error) = std::fs::write(path, value)
    {
        tracing::warn!(%error,"download failed");
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub async fn choose_image() -> Result<Option<(Vec<u8>, String, String)>, String> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let result = (|| {
            let Some(path) = rfd::FileDialog::new()
                .add_filter("Image", &["png", "jpg", "jpeg", "gif", "webp"])
                .pick_file()
            else {
                return Ok(None);
            };
            let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
            let media_type = match image::guess_format(&bytes).map_err(|error| error.to_string())? {
                image::ImageFormat::Png => "image/png",
                image::ImageFormat::Jpeg => "image/jpeg",
                image::ImageFormat::Gif => "image/gif",
                image::ImageFormat::WebP => "image/webp",
                _ => return Err("Unsupported image format".into()),
            };
            let filename = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "avatar".into());
            Ok(Some((bytes, media_type.to_owned(), filename)))
        })();
        let _ = sender.send(result);
    });
    receiver
        .await
        .map_err(|_| "Image picker stopped".to_owned())?
}
