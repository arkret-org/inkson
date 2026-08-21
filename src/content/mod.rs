//! Rich content rendering for message bodies.
//!
//! Task A3 (round 28). Uses a structured pipeline:
//!
//! 1. Protocol chat uses [`parse_message_body_with_format`] to dispatch from the Content Block's
//!    declared format. [`parse_local_preview_body`] retains heuristic parsing only for local editor
//!    previews that do not carry a protocol discriminator.
//! 2. [`render_blocks`] turns those blocks into a Dioxus `Element` for inclusion inside the
//!    existing message-body container.
//!
//! Out of scope for this increment: OpenGraph fetching, syntax
//! highlighting, lightbox interactions.

pub mod renderer;

pub(crate) use renderer::encode_long_text_marker;
pub use renderer::{
    ContentBlock, parse_local_preview_body, parse_message_body, parse_message_body_with_format,
    render_blocks,
};
