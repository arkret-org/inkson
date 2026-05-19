//! Rich content rendering for message bodies (timeline + chat).
//!
//! Task A3 (round 28). Uses a structured pipeline:
//!
//! 1. [`parse_message_body`] applies a small set of heuristics to split
//!    the body into a `Vec<ContentBlock>` — attachment markers become
//!    `Image` / `Video` / `Audio` / generic `Attachment` blocks, bare
//!    URLs become `LinkPreview` placeholders, and the remaining text is
//!    handed to pulldown-cmark to render as Markdown.
//! 2. [`render_blocks`] turns those blocks into a Dioxus `Element` for
//!    inclusion inside the existing message-body container.
//!
//! Out of scope for this increment: OpenGraph fetching, syntax
//! highlighting, lightbox interactions. They're tracked as follow-ups in
//! `_claude_todos.md`.

pub mod renderer;

pub use renderer::{ContentBlock, parse_message_body, render_blocks};
