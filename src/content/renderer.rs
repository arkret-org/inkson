//! Message content parser + RSX renderer.
//!
//! See the module-level doc on [`crate::content`] for the design intent
//! and the boundaries set by task A3.

use dioxus::prelude::*;
use pulldown_cmark::{CowStr, Event, Options, Parser as MdParser, html as md_html};

use crate::{api::ContrixApi, config::LocalConfigStore};

/// Marker recognised in message bodies that points at an uploaded blob.
///
/// Produced by `views::chat::ondrop` and `views::timeline::ondrop` when
/// the composer drag-drop pipeline uploads bytes via
/// `ContrixApi::upload_blob_bytes` (A6.2).
const ATTACHMENT_MARKER_PREFIX: &str = "[Attachment:";
const ATTACHMENT_MARKER_SUFFIX: char = ']';

/// Structured content unit emitted by [`parse_message_body`].
///
/// Every variant carries enough information for [`render_blocks`] to
/// produce a self-contained Dioxus subtree without re-parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentBlock {
    /// Raw plaintext — used when the body contains no markdown
    /// constructs and no detectable URLs. Rendered as a `<p>` so the
    /// surrounding flow keeps a baseline.
    Text(String),
    /// HTML rendered by pulldown-cmark from a markdown source. Raw
    /// HTML pass-through is disabled at the parser level (see
    /// [`markdown_to_safe_html`]).
    Markdown(String),
    /// Image attachment (heuristic — extension hint or explicit media
    /// type).
    Image {
        blob_ref: String,
        alt: Option<String>,
    },
    /// Video attachment.
    Video {
        blob_ref: String,
        media_type: String,
    },
    /// Audio attachment.
    Audio {
        blob_ref: String,
        media_type: String,
    },
    /// Fenced markdown code block surfaced separately so it can carry
    /// language metadata and (eventually) a copy-to-clipboard button.
    /// Currently only emitted by tests that fabricate the variant —
    /// the parser folds fenced code into the surrounding `Markdown`
    /// block because pulldown-cmark already renders `<pre><code>`.
    CodeBlock { lang: Option<String>, code: String },
    /// Placeholder for an external link preview. The real OG-fetch
    /// pipeline is a follow-up; for now we render the URL itself with a
    /// clickable anchor so it's at least navigable.
    LinkPreview {
        url: String,
        title: Option<String>,
        description: Option<String>,
    },
    /// Attachment marker whose mime type we can't classify — rendered
    /// as a download link via [`ContentBlock::Attachment`].
    Attachment {
        blob_ref: String,
        media_type: Option<String>,
    },
    /// Fallback for malformed / unrecognised content. Rendered inside
    /// a `<pre>` to make the raw payload obvious for debugging.
    Unknown(String),
}

/// Parse a message body into a vector of [`ContentBlock`]s.
///
/// The grammar is intentionally tiny: split on lines, lift any
/// attachment markers and bare URLs into their own blocks, and feed
/// everything else through pulldown-cmark. This keeps the renderer
/// predictable and avoids the temptation to grow a bespoke parser.
pub fn parse_message_body(body: &str) -> Vec<ContentBlock> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut blocks: Vec<ContentBlock> = Vec::new();
    // Buffer of consecutive non-attachment lines that will be folded
    // into a single Markdown/Text block.
    let mut text_buf: Vec<String> = Vec::new();

    let flush_text = |buf: &mut Vec<String>, out: &mut Vec<ContentBlock>| {
        if buf.is_empty() {
            return;
        }
        let chunk = buf.join("\n");
        buf.clear();
        push_text_chunk(&chunk, out);
    };

    for line in trimmed.split('\n') {
        if let Some(block) =
            parse_attachment_line(line).or_else(|| parse_markdown_blob_image_line(line))
        {
            flush_text(&mut text_buf, &mut blocks);
            blocks.push(block);
        } else {
            text_buf.push(line.to_owned());
        }
    }
    flush_text(&mut text_buf, &mut blocks);

    blocks
}

/// Add a free-text chunk to `out`, lifting bare URLs into
/// [`ContentBlock::LinkPreview`] entries and converting the rest into
/// either [`ContentBlock::Markdown`] (if it contains markdown markers
/// or a URL) or [`ContentBlock::Text`].
fn push_text_chunk(chunk: &str, out: &mut Vec<ContentBlock>) {
    let chunk = chunk.trim_matches('\n');
    if chunk.trim().is_empty() {
        return;
    }

    // Pull out bare URLs first. Anything left is fed to markdown.
    let (cleaned, urls) = extract_bare_urls(chunk);
    let prose = cleaned.trim().to_owned();

    if !prose.is_empty() {
        if looks_like_markdown(&prose) {
            let html = markdown_to_safe_html(&prose);
            out.push(ContentBlock::Markdown(html));
        } else {
            out.push(ContentBlock::Text(prose));
        }
    }

    for url in urls {
        out.push(ContentBlock::LinkPreview {
            url,
            title: None,
            description: None,
        });
    }
}

/// Recognise the `[Attachment: <blob_ref>]` marker emitted by the
/// composer drag-drop pipeline. Returns `None` for lines that do not
/// match so they can be funneled into the markdown path.
fn parse_attachment_line(line: &str) -> Option<ContentBlock> {
    let line = line.trim();
    if !line.starts_with(ATTACHMENT_MARKER_PREFIX) || !line.ends_with(ATTACHMENT_MARKER_SUFFIX) {
        return None;
    }
    // Strip prefix + trailing `]`.
    let inner = &line[ATTACHMENT_MARKER_PREFIX.len()..line.len() - 1];
    let blob_ref = inner.trim().to_owned();
    if blob_ref.is_empty() {
        return None;
    }

    let kind = classify_blob_ref(&blob_ref);
    Some(kind)
}

/// Recognise Markdown image lines emitted by rich editors when the image
/// target is one of our authenticated blob refs:
/// `![alt](cx:blob:sha256:...#image/png)`.
fn parse_markdown_blob_image_line(line: &str) -> Option<ContentBlock> {
    let line = line.trim();
    if !line.starts_with("![") || !line.ends_with(')') {
        return None;
    }
    let split = line.find("](")?;
    let alt = line[2..split].trim().to_owned();
    let blob_ref = line[split + 2..line.len() - 1].trim();
    if !blob_ref.starts_with("cx:blob:") {
        return None;
    }
    match classify_blob_ref(blob_ref) {
        ContentBlock::Image { blob_ref, .. } => Some(ContentBlock::Image {
            blob_ref,
            alt: if alt.is_empty() { None } else { Some(alt) },
        }),
        other => Some(other),
    }
}

/// Map a blob ref to a [`ContentBlock`] using the extension hint that
/// may be embedded after the last `.` or `/` in the ref. soland's
/// canonical `cx:blob:<sha256>` form carries no extension, so the
/// classifier degrades gracefully into the generic `Attachment` block.
fn classify_blob_ref(blob_ref: &str) -> ContentBlock {
    let lower = blob_ref.to_ascii_lowercase();
    // Look at the last few characters for an extension hint. We
    // accept either a literal `.ext` suffix or a media-type fragment
    // like `cx:blob:abc#image/png` to keep the heuristic forgiving.
    if let Some(hash_idx) = lower.rfind('#') {
        let hint = &lower[hash_idx + 1..];
        if hint.starts_with("image/") {
            return ContentBlock::Image {
                blob_ref: blob_ref.to_owned(),
                alt: None,
            };
        }
        if hint.starts_with("video/") {
            return ContentBlock::Video {
                blob_ref: blob_ref.to_owned(),
                media_type: hint.to_owned(),
            };
        }
        if hint.starts_with("audio/") {
            return ContentBlock::Audio {
                blob_ref: blob_ref.to_owned(),
                media_type: hint.to_owned(),
            };
        }
        return ContentBlock::Attachment {
            blob_ref: blob_ref.to_owned(),
            media_type: Some(hint.to_owned()),
        };
    }

    // Fall back to extension sniffing.
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "svg" => ContentBlock::Image {
            blob_ref: blob_ref.to_owned(),
            alt: None,
        },
        "mp4" | "webm" | "mov" | "mkv" => ContentBlock::Video {
            blob_ref: blob_ref.to_owned(),
            media_type: format!("video/{ext}"),
        },
        "mp3" | "wav" | "ogg" | "flac" | "m4a" => ContentBlock::Audio {
            blob_ref: blob_ref.to_owned(),
            media_type: format!("audio/{ext}"),
        },
        _ => ContentBlock::Attachment {
            blob_ref: blob_ref.to_owned(),
            media_type: None,
        },
    }
}

/// Pull bare `http(s)://` URLs out of `chunk` and return the cleaned
/// remainder plus the list of extracted URLs (in source order).
fn extract_bare_urls(chunk: &str) -> (String, Vec<String>) {
    let mut urls: Vec<String> = Vec::new();
    let mut cleaned = String::with_capacity(chunk.len());
    for token in chunk.split_whitespace() {
        if is_bare_url(token) {
            urls.push(strip_trailing_punct(token).to_owned());
            cleaned.push(' ');
        } else {
            cleaned.push_str(token);
            cleaned.push(' ');
        }
    }
    (cleaned.trim().to_owned(), urls)
}

fn is_bare_url(token: &str) -> bool {
    let stripped = strip_trailing_punct(token);
    (stripped.starts_with("http://") || stripped.starts_with("https://"))
        && stripped.len() > 10
        && !stripped.contains('<')
        && !stripped.contains('>')
}

fn strip_trailing_punct(s: &str) -> &str {
    s.trim_end_matches(|c: char| matches!(c, '.' | ',' | ')' | ']' | '!' | '?' | ';' | ':'))
}

fn blob_ref_media_type_hint(blob_ref: &str) -> Option<String> {
    let lower = blob_ref.to_ascii_lowercase();
    if let Some(hash_idx) = lower.rfind('#') {
        let hint = &lower[hash_idx + 1..];
        if hint.contains('/') {
            return Some(hint.to_owned());
        }
    }
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "png" => Some("image/png".to_owned()),
        "jpg" | "jpeg" => Some("image/jpeg".to_owned()),
        "gif" => Some("image/gif".to_owned()),
        "webp" => Some("image/webp".to_owned()),
        "bmp" => Some("image/bmp".to_owned()),
        "svg" => Some("image/svg+xml".to_owned()),
        "mp4" => Some("video/mp4".to_owned()),
        "webm" => Some("video/webm".to_owned()),
        "mp3" => Some("audio/mpeg".to_owned()),
        "wav" => Some("audio/wav".to_owned()),
        "ogg" => Some("audio/ogg".to_owned()),
        _ => None,
    }
}

/// Cheap heuristic — does this prose chunk look like markdown? We
/// fall back to plain text when none of the common markers appear so
/// that simple "hi there" messages don't get wrapped in `<p>` markup
/// they didn't ask for.
fn looks_like_markdown(prose: &str) -> bool {
    prose.contains("**")
        || prose.contains("__")
        || prose.contains('`')
        || prose.contains("\n#")
        || prose.starts_with('#')
        || prose.contains("\n- ")
        || prose.starts_with("- ")
        || prose.contains("\n* ")
        || prose.starts_with("* ")
        || prose.contains("\n1. ")
        || prose.starts_with("1. ")
        || prose.contains("\n> ")
        || prose.starts_with("> ")
        || prose.contains("](")
        || prose.contains("\n```")
        || prose.starts_with("```")
}

/// Render markdown to HTML with pulldown-cmark, escaping any raw HTML
/// the source tried to smuggle through.
///
/// pulldown-cmark 0.10 follows CommonMark and emits `Event::Html` /
/// `Event::InlineHtml` for any embedded `<tag>…</tag>` it finds. Since
/// the rendered HTML is handed to `dangerous_inner_html` we cannot let
/// arbitrary `<script>` / `<iframe>` / event-handler attributes
/// through — so we map those events into their text-escaped form
/// before `push_html` writes them out.
fn markdown_to_safe_html(src: &str) -> String {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts.insert(Options::ENABLE_FOOTNOTES);

    let parser = MdParser::new_ext(src, opts).map(|event| match event {
        // Convert raw HTML to plain text. `push_html` already escapes
        // text events through `escape_html_body_text`, so we hand it
        // the raw source and let it do the encoding once. This keeps
        // `<script>alert(1)</script>` rendering as the literal
        // characters instead of executing.
        Event::Html(raw) => Event::Text(CowStr::from(raw.into_string())),
        Event::InlineHtml(raw) => Event::Text(CowStr::from(raw.into_string())),
        other => other,
    });

    let mut out = String::with_capacity(src.len() + 32);
    md_html::push_html(&mut out, parser);
    out
}

async fn authenticated_blob_data_url(blob_ref: &str, media_type: &str) -> anyhow::Result<String> {
    let config = LocalConfigStore::default().load();
    let token = config.session_token.trim().to_owned();
    if token.is_empty() {
        anyhow::bail!("no authenticated session for blob download");
    }
    let bytes = ContrixApi::new(&config.server_url)?
        .with_bearer(token)
        .get_blob_bytes(blob_ref)
        .await?;
    let mime = if media_type.trim().is_empty() {
        "application/octet-stream"
    } else {
        media_type.trim()
    };
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
    Ok(format!("data:{mime};base64,{encoded}"))
}

/// RSX renderer for a slice of [`ContentBlock`]s.
pub fn render_blocks(blocks: &[ContentBlock]) -> Element {
    let owned: Vec<ContentBlock> = blocks.to_vec();
    rsx! {
        div { class: "content-blocks", "data-testid": "content-blocks",
            for (idx, block) in owned.into_iter().enumerate() {
                {render_single_block(idx, block)}
            }
        }
    }
}

fn render_single_block(idx: usize, block: ContentBlock) -> Element {
    let key = format!("content-block-{idx}");
    match block {
        ContentBlock::Text(text) => rsx! {
            p {
                key: "{key}",
                class: "content-block-text",
                "data-testid": "content-block-text",
                "{text}"
            }
        },
        ContentBlock::Markdown(html) => rsx! {
            div {
                key: "{key}",
                class: "content-block-markdown",
                "data-testid": "content-block-markdown",
                dangerous_inner_html: "{html}",
            }
        },
        ContentBlock::Image { blob_ref, alt } => {
            let alt_text = alt.unwrap_or_else(|| blob_ref.clone());
            rsx! {
                AuthenticatedBlobImage {
                    key: "{key}",
                    blob_ref,
                    alt_text,
                }
            }
        }
        ContentBlock::Video {
            blob_ref,
            media_type,
        } => {
            rsx! {
                AuthenticatedBlobVideo {
                    key: "{key}",
                    blob_ref,
                    media_type,
                }
            }
        }
        ContentBlock::Audio {
            blob_ref,
            media_type,
        } => {
            rsx! {
                AuthenticatedBlobAudio {
                    key: "{key}",
                    blob_ref,
                    media_type,
                }
            }
        }
        ContentBlock::CodeBlock { lang, code } => {
            let lang_class = match lang.as_deref() {
                Some(l) if !l.is_empty() => format!("lang-{l}"),
                _ => "lang-plain".to_owned(),
            };
            let copy_label = crate::i18n::tr("content.code.copy");
            rsx! {
                div {
                    key: "{key}",
                    class: "content-block-code",
                    "data-testid": "content-block-code",
                    pre {
                        code { class: "{lang_class}", "{code}" }
                    }
                    button {
                        r#type: "button",
                        class: "secondary content-block-code-copy",
                        "data-testid": "content-block-code-copy",
                        title: "{copy_label}",
                        "{copy_label}"
                    }
                }
            }
        }
        ContentBlock::LinkPreview {
            url,
            title,
            description,
        } => {
            let title_text = title.unwrap_or_else(|| url.clone());
            let description_text = description.unwrap_or_default();
            rsx! {
                a {
                    key: "{key}",
                    class: "content-block-link-preview",
                    "data-testid": "content-block-link-preview",
                    href: "{url}",
                    target: "_blank",
                    rel: "noopener noreferrer",
                    div { class: "content-block-link-preview-title", "{title_text}" }
                    div { class: "content-block-link-preview-url muted", "{url}" }
                    if !description_text.is_empty() {
                        div { class: "content-block-link-preview-description",
                            "{description_text}"
                        }
                    }
                }
            }
        }
        ContentBlock::Attachment {
            blob_ref,
            media_type,
        } => {
            let mime = media_type.unwrap_or_else(|| "application/octet-stream".to_owned());
            rsx! {
                AuthenticatedBlobDownload {
                    key: "{key}",
                    blob_ref,
                    media_type: mime,
                }
            }
        }
        ContentBlock::Unknown(raw) => rsx! {
            pre {
                key: "{key}",
                class: "content-block-unknown",
                "data-testid": "content-block-unknown",
                "{raw}"
            }
        },
    }
}

#[component]
pub fn AuthenticatedBlobImage(blob_ref: String, alt_text: String) -> Element {
    let mut src = use_signal(String::new);
    let mut status = use_signal(String::new);
    let blob_for_effect = blob_ref.clone();
    use_effect(move || {
        let blob = blob_for_effect.clone();
        let media_type = blob_ref_media_type_hint(&blob).unwrap_or_else(|| "image/png".to_owned());
        spawn(async move {
            match authenticated_blob_data_url(&blob, &media_type).await {
                Ok(url) => {
                    src.set(url);
                    status.set(String::new());
                }
                Err(err) => status.set(err.to_string()),
            }
        });
    });
    let broken_label = crate::i18n::tr("content.image.broken");
    rsx! {
        div {
            class: "content-block-image",
            "data-testid": "content-block-image",
            if !src().is_empty() {
                img {
                    loading: "lazy",
                    src: "{src}",
                    alt: "{alt_text}",
                    title: "{blob_ref}",
                }
            } else {
                div { class: "muted", "data-testid": "content-block-blob-loading", "{blob_ref}" }
            }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "content-block-blob-error", "{broken_label}: {status}" }
            }
        }
    }
}

#[component]
fn AuthenticatedBlobVideo(blob_ref: String, media_type: String) -> Element {
    let mut src = use_signal(String::new);
    let mut status = use_signal(String::new);
    let blob_for_effect = blob_ref.clone();
    let media_for_effect = media_type.clone();
    use_effect(move || {
        let blob = blob_for_effect.clone();
        let mime = media_for_effect.clone();
        spawn(async move {
            match authenticated_blob_data_url(&blob, &mime).await {
                Ok(url) => {
                    src.set(url);
                    status.set(String::new());
                }
                Err(err) => status.set(err.to_string()),
            }
        });
    });
    let unsupported = crate::i18n::tr("content.video.unsupported");
    rsx! {
        div {
            class: "content-block-video",
            "data-testid": "content-block-video",
            if !src().is_empty() {
                video {
                    controls: true,
                    preload: "metadata",
                    source { src: "{src}", r#type: "{media_type}" }
                    "{unsupported}"
                }
            }
            div { class: "muted", "{blob_ref}" }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "content-block-blob-error", "{status}" }
            }
        }
    }
}

#[component]
fn AuthenticatedBlobAudio(blob_ref: String, media_type: String) -> Element {
    let mut src = use_signal(String::new);
    let mut status = use_signal(String::new);
    let blob_for_effect = blob_ref.clone();
    let media_for_effect = media_type.clone();
    use_effect(move || {
        let blob = blob_for_effect.clone();
        let mime = media_for_effect.clone();
        spawn(async move {
            match authenticated_blob_data_url(&blob, &mime).await {
                Ok(url) => {
                    src.set(url);
                    status.set(String::new());
                }
                Err(err) => status.set(err.to_string()),
            }
        });
    });
    let unsupported = crate::i18n::tr("content.audio.unsupported");
    rsx! {
        div {
            class: "content-block-audio",
            "data-testid": "content-block-audio",
            if !src().is_empty() {
                audio {
                    controls: true,
                    preload: "metadata",
                    source { src: "{src}", r#type: "{media_type}" }
                    "{unsupported}"
                }
            }
            div { class: "muted", "{blob_ref}" }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "content-block-blob-error", "{status}" }
            }
        }
    }
}

#[component]
fn AuthenticatedBlobDownload(blob_ref: String, media_type: String) -> Element {
    let mut href = use_signal(String::new);
    let mut status = use_signal(String::new);
    let download_label = crate::i18n::tr("content.attachment.download");
    rsx! {
        div {
            class: "content-block-attachment",
            "data-testid": "content-block-attachment",
            span { class: "muted", "{media_type}" }
            span { " " }
            span { "{blob_ref}" }
            span { " " }
            if href().is_empty() {
                button {
                    r#type: "button",
                    class: "secondary",
                    "data-testid": "content-block-attachment-download",
                    title: "{download_label}",
                    onclick: {
                        let blob = blob_ref.clone();
                        let mime = media_type.clone();
                        move |_| {
                            status.set("Downloading...".to_owned());
                            let blob = blob.clone();
                            let mime = mime.clone();
                            spawn(async move {
                                match authenticated_blob_data_url(&blob, &mime).await {
                                    Ok(url) => {
                                        href.set(url);
                                        status.set(String::new());
                                    }
                                    Err(err) => status.set(err.to_string()),
                                }
                            });
                        }
                    },
                    "{download_label}"
                }
            } else {
                a {
                    class: "secondary",
                    "data-testid": "content-block-attachment-download-link",
                    href: "{href}",
                    download: "{blob_ref}",
                    "{download_label}"
                }
            }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "content-block-blob-error", "{status}" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_message_body_handles_plain_text() {
        let blocks = parse_message_body("hello world");
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Text(t) => assert_eq!(t, "hello world"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn parse_message_body_returns_empty_for_blank_input() {
        assert!(parse_message_body("").is_empty());
        assert!(parse_message_body("   \n\n  ").is_empty());
    }

    #[test]
    fn parse_message_body_extracts_markdown_headings() {
        let body = "# Title\n\nsome **bold** body";
        let blocks = parse_message_body(body);
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Markdown(html) => {
                assert!(html.contains("<h1>"), "missing <h1> in {html}");
                assert!(html.contains("<strong>"), "missing <strong> in {html}");
            }
            other => panic!("expected Markdown, got {other:?}"),
        }
    }

    #[test]
    fn parse_message_body_recognizes_attachment_marker_image_extension() {
        let body = "look at this:\n[Attachment: cx:blob:abcdef.png]";
        let blocks = parse_message_body(body);
        assert_eq!(blocks.len(), 2, "blocks: {blocks:?}");
        match &blocks[1] {
            ContentBlock::Image { blob_ref, .. } => {
                assert_eq!(blob_ref, "cx:blob:abcdef.png");
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn parse_message_body_recognizes_attachment_marker_video_extension() {
        let blocks = parse_message_body("[Attachment: cx:blob:cafefade.mp4]");
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Video {
                blob_ref,
                media_type,
            } => {
                assert_eq!(blob_ref, "cx:blob:cafefade.mp4");
                assert_eq!(media_type, "video/mp4");
            }
            other => panic!("expected Video, got {other:?}"),
        }
    }

    #[test]
    fn parse_message_body_recognizes_attachment_marker_audio_extension() {
        let blocks = parse_message_body("[Attachment: cx:blob:deadbeef.mp3]");
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Audio { media_type, .. } => {
                assert_eq!(media_type, "audio/mp3");
            }
            other => panic!("expected Audio, got {other:?}"),
        }
    }

    #[test]
    fn parse_message_body_recognizes_media_type_hint_fragment() {
        let blocks = parse_message_body("[Attachment: cx:blob:abc#image/png]");
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Image { blob_ref, .. } => {
                assert_eq!(blob_ref, "cx:blob:abc#image/png");
            }
            other => panic!("expected Image (from media-type hint), got {other:?}"),
        }
    }

    #[test]
    fn parse_message_body_recognizes_markdown_blob_image() {
        let blocks = parse_message_body("![Launch image](cx:blob:abc#image/png)");
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Image { blob_ref, alt } => {
                assert_eq!(blob_ref, "cx:blob:abc#image/png");
                assert_eq!(alt.as_deref(), Some("Launch image"));
            }
            other => panic!("expected Image (from markdown blob image), got {other:?}"),
        }
    }

    #[test]
    fn parse_message_body_extracts_bare_url_as_link_preview() {
        let body = "check this https://example.com/post out";
        let blocks = parse_message_body(body);
        assert!(
            blocks.iter().any(|b| matches!(
                b,
                ContentBlock::LinkPreview { url, .. } if url == "https://example.com/post"
            )),
            "no LinkPreview block in {blocks:?}"
        );
    }

    #[test]
    fn parse_message_body_falls_back_to_attachment_for_unhinted_blob() {
        let blocks = parse_message_body("[Attachment: cx:blob:opaque-no-extension]");
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Attachment {
                blob_ref,
                media_type,
            } => {
                assert_eq!(blob_ref, "cx:blob:opaque-no-extension");
                assert!(media_type.is_none());
            }
            other => panic!("expected Attachment, got {other:?}"),
        }
    }

    #[test]
    fn parse_message_body_falls_back_to_unknown_for_unrecognized_attachment() {
        // Malformed marker — missing closing bracket. The parser
        // should leave it as plain text so the user can still see what
        // was sent (and not silently swallow the payload).
        let blocks = parse_message_body("[Attachment: cx:blob:bad");
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Text(t) => assert!(t.contains("Attachment")),
            other => panic!("expected Text fallback, got {other:?}"),
        }
    }

    #[test]
    fn parse_message_body_handles_mixed_content_round_trip() {
        let body = concat!(
            "# Heading\n",
            "\n",
            "see https://example.com/ref for context\n",
            "[Attachment: cx:blob:photo.jpg]\n",
            "[Attachment: cx:blob:clip.mp4]\n",
            "plain trailing line\n",
        );
        let blocks = parse_message_body(body);
        // Expect: Markdown (heading) + LinkPreview + Image + Video +
        // (Text or Markdown for trailing line). We don't pin the
        // exact count to avoid brittleness — assert the variants we
        // care about appear at least once.
        let has_markdown = blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::Markdown(_)));
        let has_link = blocks.iter().any(
            |b| matches!(b, ContentBlock::LinkPreview { url, .. } if url.starts_with("https://")),
        );
        let has_image = blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::Image { .. }));
        let has_video = blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::Video { .. }));
        assert!(has_markdown, "missing Markdown: {blocks:?}");
        assert!(has_link, "missing LinkPreview: {blocks:?}");
        assert!(has_image, "missing Image: {blocks:?}");
        assert!(has_video, "missing Video: {blocks:?}");
    }

    #[test]
    fn markdown_to_safe_html_escapes_raw_html() {
        // ENABLE_RAW_HTML is deliberately off, so a `<script>` tag in
        // the source must be escaped rather than passed through.
        let html = markdown_to_safe_html("<script>alert(1)</script>");
        assert!(
            !html.contains("<script>"),
            "raw HTML leaked through: {html}"
        );
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn extract_bare_urls_strips_trailing_punctuation() {
        let (cleaned, urls) = extract_bare_urls("visit https://example.com/foo, please");
        assert_eq!(urls, vec!["https://example.com/foo".to_owned()]);
        assert!(cleaned.contains("visit"));
        assert!(cleaned.contains("please"));
    }

    #[test]
    fn looks_like_markdown_detects_common_markers() {
        assert!(looks_like_markdown("# heading"));
        assert!(looks_like_markdown("**bold**"));
        assert!(looks_like_markdown("- item"));
        assert!(looks_like_markdown("[link](https://example.com)"));
        assert!(!looks_like_markdown("just plain prose"));
    }
}
