//! Document view — block editor backed by a document Morph projection.
//!
//! - Every edit is mirrored to `LocalStateStore.private_data` so the draft survives navigation and
//!   offline use.
//! - Save Version emits a real `ck.morph.create` (first time) or `ck.morph.update` (subsequent
//!   saves). The morph_id is persisted per-Realm so subsequent saves target the same Morph.
//! - The header sync badge reports the result of the most recent submit: `Synced` / `Pending sync`
//!   / `Local draft`. Failed submits fall back to local draft without losing the user's edits.
//!
//! G3.Y4 — collaborative surfaces:
//!
//! The panel now renders cursor markers (self + per-remote-actor), a
//! presence sidebar listing actors actively editing the document, a
//! comment composer wired to range start/end inputs, version restore /
//! diff buttons, and the supporting state machines for both. The data
//! is sourced from soland's document Morph projection when a `ck:morph:*`
//! route or persisted document id is available, with local draft fallback
//! for offline creation.

mod model;
mod panel;
mod projection;

#[cfg(test)]
mod tests;

pub use model::{DocumentCommentReply, DocumentCommentThread, RemoteCursor};
pub use panel::DocumentPanel;
pub use projection::{document_collaboration_enabled, parse_comment_range, restore_status_label};
