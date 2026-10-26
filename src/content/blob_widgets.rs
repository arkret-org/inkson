//! Session-fenced authenticated content for both application hosts.
use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::{InksonContext, View, widgets};

pub(super) fn blob_bytes(
    context: Rc<InksonContext>,
    blob: String,
) -> impl std::future::Future<Output = std::result::Result<Vec<u8>, String>> + 'static {
    let generation = context.session_generation.get();
    let account = context.active_account.get();
    let token = context.token.get();
    let base = context.base_url.get();
    async move {
        if token.trim().is_empty() || !context.session_matches(generation, &account) {
            return Err("No active authenticated session for this attachment.".into());
        }
        let api = crate::transport::auth::authed_api_ready(&base, token)
            .await
            .map_err(|error| crate::api_error::display_user_facing(&error))?;
        if !context.session_matches(generation, &account) {
            return Err("The account changed while preparing this attachment.".into());
        }
        let http = api
            .sdk_http_client()
            .map_err(|error| crate::api_error::display_user_facing(&error))?;
        let result = crate::transport::EndpointClients::from_http(http)
            .blob()
            .get_bytes(&blob)
            .await
            .map_err(|error| crate::api_error::display_user_facing(&error));
        if !context.session_matches(generation, &account) {
            return Err("The account changed while loading this attachment.".into());
        }
        result
    }
}

pub(crate) fn blob_source(
    scope: &Scope,
    context: Rc<InksonContext>,
    blob: String,
    mime: String,
) -> widgets::Resource<String> {
    #[cfg(not(target_arch = "wasm32"))]
    let registration = Rc::new(std::cell::RefCell::new(None::<String>));
    #[cfg(not(target_arch = "wasm32"))]
    let owner = scope.downgrade();
    widgets::resource(scope, move || {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(previous) = registration.borrow_mut().take() {
            context.revoke_native_image(&previous);
        }
        let request = blob_bytes(context.clone(), blob.clone());
        let mime = mime.clone();
        #[cfg(not(target_arch = "wasm32"))]
        let native_context = context.clone();
        #[cfg(not(target_arch = "wasm32"))]
        let native_owner = owner.clone();
        #[cfg(not(target_arch = "wasm32"))]
        let registration = registration.clone();
        async move {
            let bytes = request.await?;
            #[cfg(not(target_arch = "wasm32"))]
            if mime.starts_with("image/") {
                // blob_bytes has already rechecked the authenticated account
                // after transport completion. The provider separately fences
                // its asynchronous delivery to the registered window/epoch.
                let scope = native_owner
                    .upgrade()
                    .ok_or("The image owner was retired.")?;
                let url = native_context.register_native_image(&scope, &mime, bytes)?;
                *registration.borrow_mut() = Some(url.clone());
                return Ok(url);
            }
            Ok(format!(
                "data:{mime};base64,{}",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
            ))
        }
    })
}

/// Preserve browser data-image sources; native image bytes are owned by the
/// exact rendering scope and are never placed in a filesystem cache.
pub(crate) fn scoped_image_url(
    scope: &Scope,
    context: &Rc<InksonContext>,
    source: &str,
) -> std::result::Result<String, String> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (scope, context);
        Ok(source.to_owned())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let (mime, bytes) = image_payload(source)?;
        context.register_native_image(scope, mime, bytes)
    }
}
#[cfg(not(target_arch = "wasm32"))]
fn image_payload(source: &str) -> std::result::Result<(&str, Vec<u8>), String> {
    use base64::Engine as _;
    const LIMIT: usize = 8 * 1024 * 1024;
    let (header, encoded) = source
        .strip_prefix("data:")
        .and_then(|value| value.split_once(','))
        .ok_or("The image source is unavailable.")?;
    let mime = header
        .strip_suffix(";base64")
        .filter(|mime| mime.starts_with("image/"))
        .ok_or("The image encoding is unavailable.")?;
    if encoded.len() > LIMIT.div_ceil(3) * 4 {
        return Err("The image exceeds the native byte limit.".into());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "The image payload is invalid.")?;
    if bytes.len() > LIMIT {
        return Err("The image exceeds the native byte limit.".into());
    }
    Ok((mime, bytes))
}

pub fn authenticated_blob_image(
    scope: &Scope,
    context: Rc<InksonContext>,
    blob_ref: String,
    alt_text: String,
) -> View {
    let mime =
        super::renderer::blob_ref_media_type_hint(&blob_ref).unwrap_or_else(|| "image/png".into());
    let source = blob_source(scope, context.clone(), blob_ref.clone(), mime);
    widgets::resource_content(
        context,
        "authenticated-image",
        source,
        "common.loading",
        move |_, url| {
            Box::new(
                image()
                    .class("content-block-image")
                    .source(url)
                    .alt(alt_text.clone()),
            )
        },
    )
}

pub(super) fn media(
    scope: &Scope,
    context: Rc<InksonContext>,
    blob: String,
    mime: String,
    video: bool,
) -> View {
    let source = blob_source(scope, context.clone(), blob.clone(), mime.clone());
    widgets::resource_content(
        context.clone(),
        "authenticated-media",
        source,
        "common.loading",
        move |scope, url| {
            #[cfg(target_arch = "wasm32")]
            {
                browser_media(scope, url, video)
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                widgets::stack(
                    "content-block-media",
                    vec![
                        widgets::paragraph(
                            "muted",
                            "This media can be saved and opened in your media player.",
                        ),
                        native_media(scope, url, video),
                        download(scope, context.clone(), blob.clone(), mime.clone()),
                    ],
                )
            }
        },
    )
}

#[cfg(target_arch = "wasm32")]
fn browser_media(scope: &Scope, source: String, video: bool) -> View {
    let id = format!("inkson-media-{}", scope.id().slot());
    let host = id.clone();
    let Ok(identity) = glory::render::SemanticId::new(id) else {
        return widgets::paragraph("error", "The media presentation identity is unavailable.");
    };
    Box::new(
        view()
            .class(if video {
                "content-block-video"
            } else {
                "content-block-audio"
            })
            .semantics(Some(Box::new(glory::render::Semantics {
                id: Some(identity),
                ..Default::default()
            })))
            .fill(widget(move |scope| {
                let weak = scope.downgrade();
                let host = host.clone();
                let source = source.clone();
                let _ = scope.spawn(async move {
                    crate::runtime_helpers::sleep_for(std::time::Duration::ZERO).await;
                    let Some(scope) = weak.upgrade() else { return };
                    if let Some(document) = web_sys::window().and_then(|window| window.document())
                        && let Some(host) = document.get_element_by_id(&host)
                        && let Ok(media) =
                            document.create_element(if video { "video" } else { "audio" })
                    {
                        let _ = media.set_attribute("src", &source);
                        let _ = media.set_attribute("controls", "");
                        let _ = media.set_attribute("preload", "metadata");
                        let _ = host.append_child(&media);
                        let _ = scope.on_cleanup(move || {
                            use wasm_bindgen::JsCast;
                            if let Some(media) = media.dyn_ref::<web_sys::HtmlMediaElement>() {
                                let _ = media.pause();
                            }
                            media.remove();
                        });
                    }
                });
                Ok(())
            })),
    )
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn media_url(scope: &Scope, source: String, video: bool) -> View {
    browser_media(scope, source, video)
}

#[cfg(not(target_arch = "wasm32"))]
fn media_payload(source: &str) -> std::result::Result<(String, Vec<u8>), String> {
    use base64::Engine as _;
    let (header, body) = source
        .strip_prefix("data:")
        .and_then(|value| value.split_once(','))
        .ok_or("The media source is unavailable.")?;
    let mime = header
        .strip_suffix(";base64")
        .ok_or("The media encoding is unavailable.")?;
    if !(mime.starts_with("audio/")
        || mime.starts_with("video/")
        || mime == "application/octet-stream")
    {
        return Err("This attachment is not an audio or video source.".into());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| "The media payload is invalid.")?;
    Ok((mime.to_owned(), bytes))
}

#[cfg(not(target_arch = "wasm32"))]
fn media_file_extension(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "mp4" | "webm" | "mp3" | "m4a" | "ogg" | "oga" | "wav" | "flac" | "aac" | "mov"
            )
        })
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn open_saved_media(path: &std::path::Path) -> std::result::Result<(), String> {
    if !media_file_extension(path) {
        return Err("The file was saved. Choose a standard audio or video filename extension to open it from Inkson.".into());
    }
    opener::open(path).map_err(|error| error.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn native_media(scope: &Scope, source: String, video: bool) -> View {
    let busy = scope.cage(false);
    let status = scope.cage(String::new());
    let owner = scope.downgrade();
    let label = if video {
        "Save and open video"
    } else {
        "Save and open audio"
    };
    let control = sapid::button()
        .unstyled()
        .class("secondary content-block-media-open")
        .label(label)
        .enabled(scope.bond(move || !busy.get()))
        .on_press(move || {
            if busy.get_untracked() {
                return;
            }
            let Some(scope) = owner.upgrade() else {
                return;
            };
            let Some(context) = crate::presentation::current_context() else {
                status.revise(|value| *value = "The media session is unavailable.".into());
                return;
            };
            let (mime, bytes) = match media_payload(&source) {
                Ok(payload) => payload,
                Err(error) => {
                    status.revise(|value| *value = error);
                    return;
                }
            };
            let generation = context.session_generation.get_untracked();
            let account = context.active_account.get_untracked();
            let owner = scope.downgrade();
            busy.revise(|value| *value = true);
            status.revise(String::clear);
            let _ = scope.spawn(async move {
                let extension = match mime.as_str() {
                    "video/mp4" => "mp4",
                    "video/webm" => "webm",
                    "audio/mpeg" => "mp3",
                    "audio/mp4" => "m4a",
                    "audio/ogg" => "ogg",
                    "audio/wav" => "wav",
                    _ if video => "webm",
                    _ => "audio",
                };
                let file = rfd::AsyncFileDialog::new()
                    .set_file_name(format!("media.{extension}"))
                    .save_file()
                    .await;
                if owner.upgrade().is_none() || !context.session_matches(generation, &account) {
                    return;
                }
                let result = if let Some(file) = file {
                    match file.write(&bytes).await {
                        Ok(()) => {
                            if owner.upgrade().is_none()
                                || !context.session_matches(generation, &account)
                            {
                                return;
                            }
                            open_saved_media(file.path())
                        }
                        Err(error) => Err(error.to_string()),
                    }
                } else {
                    Ok(())
                };
                if owner.upgrade().is_none() || !context.session_matches(generation, &account) {
                    return;
                }
                busy.revise(|value| *value = false);
                status.revise(|value| *value = result.err().unwrap_or_default());
            });
        });
    widgets::stack(
        "content-block-media",
        vec![Box::new(control), widgets::paragraph("muted", status)],
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_media_tests {
    use super::media_payload;
    #[test]
    fn automatic_media_open_does_not_accept_executable_attachment_names() {
        use std::path::Path;
        assert!(super::media_file_extension(Path::new("recording.MP4")));
        assert!(super::media_file_extension(Path::new("voice note.ogg")));
        for name in [
            "recording.mp4.exe",
            "voice.bat",
            "payload.ps1",
            "media.lnk",
            "no-extension",
        ] {
            assert!(!super::media_file_extension(Path::new(name)));
            assert!(super::open_saved_media(Path::new(name)).is_err());
        }
    }
    #[test]
    fn saved_media_uses_exact_decoded_bytes_and_rejects_non_media_sources() {
        assert_eq!(
            media_payload("data:audio/ogg;base64,AAECAwQ=").unwrap(),
            ("audio/ogg".into(), vec![0, 1, 2, 3, 4])
        );
        for value in [
            "https://example.com/media",
            "data:text/html;base64,AA==",
            "data:audio/ogg,raw",
            "data:video/mp4;base64,!!",
        ] {
            assert!(media_payload(value).is_err());
        }
    }
}

pub(super) fn download(
    scope: &Scope,
    context: Rc<InksonContext>,
    blob: String,
    mime: String,
) -> View {
    let busy = scope.cage(false);
    let status = scope.cage(String::new());
    let weak = scope.downgrade();
    let button = sapid::button()
        .unstyled()
        .class("secondary content-block-attachment-download")
        .label(context.translated(scope, "content.attachment.download"))
        .enabled(scope.bond(move || !busy.get()))
        .on_press(move || {
            if busy.get_untracked() {
                return;
            }
            let Some(scope) = weak.upgrade() else { return };
            let request = blob_bytes(context.clone(), blob.clone());
            let filename = blob
                .split('#')
                .next()
                .unwrap_or("attachment")
                .replace(':', "-");
            let mime = mime.clone();
            busy.revise(|value| *value = true);
            status.revise(String::clear);
            let _ = scope.spawn(async move {
                let result = match request.await {
                    Ok(bytes) => save_bytes(filename, mime, bytes).await,
                    Err(error) => Err(error),
                };
                busy.revise(|value| *value = false);
                status.revise(|value| *value = result.err().unwrap_or_default());
            });
        });
    widgets::stack(
        "content-block-attachment",
        vec![Box::new(button), widgets::paragraph("muted", status)],
    )
}

#[cfg(not(target_arch = "wasm32"))]
async fn save_bytes(
    filename: String,
    _mime: String,
    bytes: Vec<u8>,
) -> std::result::Result<(), String> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let result = match rfd::FileDialog::new().set_file_name(filename).save_file() {
            Some(path) => std::fs::write(path, bytes).map_err(|error| error.to_string()),
            None => Ok(()),
        };
        let _ = sender.send(result);
    });
    receiver
        .await
        .map_err(|_| "The file dialog was closed.".to_owned())?
}

#[cfg(target_arch = "wasm32")]
async fn save_bytes(
    filename: String,
    mime: String,
    bytes: Vec<u8>,
) -> std::result::Result<(), String> {
    use wasm_bindgen::JsCast;
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or("Browser document unavailable")?;
    let href = format!(
        "data:{mime};base64,{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    );
    let anchor = document
        .create_element("a")
        .map_err(|_| "Cannot create the attachment download")?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| "Cannot create the attachment download")?;
    anchor.set_href(&href);
    anchor.set_download(&filename);
    if let Some(body) = document.body() {
        body.append_child(&anchor)
            .map_err(|_| "Cannot attach the download")?;
        anchor.click();
        anchor.remove();
    }
    Ok(())
}

pub(super) fn long_text(
    scope: &Scope,
    context: Rc<InksonContext>,
    blob: String,
    fallback: String,
    markdown: bool,
) -> View {
    let source = widgets::resource(scope, move || {
        let request = blob_bytes(context.clone(), blob.clone());
        async move {
            let bytes = request.await?;
            let text = String::from_utf8(bytes)
                .map_err(|error| format!("Long text is not UTF-8: {error}"))?;
            arkret_sdk::normalize_long_text(&text).map_err(|error| error.to_string())
        }
    });
    widgets::reactive(source.data, move |_, loaded| {
        let (value, error) = match loaded {
            Some(Ok(text)) => (text, None),
            Some(Err(error)) => (fallback.clone(), Some(error)),
            None => (fallback.clone(), None),
        };
        let content = if markdown {
            super::semantic::html(&super::renderer::markdown_to_safe_html(&value))
        } else {
            widgets::paragraph("content-block-text", value)
        };
        let mut children = vec![content];
        if let Some(error) = error {
            children.push(widgets::paragraph("muted", error));
        }
        widgets::stack("content-block-long-text", children)
    })
}
