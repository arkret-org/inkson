//! Rich content rendering for message bodies.
//!
//! Task A3 (round 28). Uses a structured pipeline:
//!
//! 1. Protocol chat uses [`parse_message_body_with_format`] to dispatch from the Content Block's
//!    declared format. [`parse_local_preview_body`] retains heuristic parsing only for local editor
//!    previews that do not carry a protocol discriminator.
//! 2. [`render_blocks`] turns those blocks into Glory semantic widgets inside the existing
//!    message-body container.
//!
//! Out of scope for this increment: OpenGraph fetching, syntax
//! highlighting, lightbox interactions.

mod blob_widgets;
#[cfg(not(target_arch = "wasm32"))]
mod external_link;
pub mod renderer;
mod semantic;
pub use blob_widgets::authenticated_blob_image;
#[cfg(target_arch = "wasm32")]
pub(crate) use blob_widgets::media_url;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use blob_widgets::open_saved_media;
pub(crate) use blob_widgets::{blob_source as authenticated_blob_source, scoped_image_url};
pub(crate) use renderer::encode_long_text_marker;
pub use renderer::{
    ContentBlock, parse_local_preview_body, parse_message_body, parse_message_body_with_format,
    render_blocks,
};
