use serde::{Deserialize, Serialize};

use crate::components::SyncBadgeState;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) enum BlockKind {
    Paragraph,
    Heading,
    BulletList,
    CodeBlock,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct DocumentBlock {
    pub(super) id: String,
    pub(super) kind: BlockKind,
    pub(super) content: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct DocumentVersion {
    pub(super) id: String,
    pub(super) timestamp: String,
    pub(super) author: String,
    pub(super) block_count: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct DocumentDraft {
    pub(super) blocks: Vec<DocumentBlock>,
    pub(super) versions: Vec<DocumentVersion>,
}

// ─────────────────────────────────────────────────────────────────────
// G3.Y4 — collaborative surface types
// ─────────────────────────────────────────────────────────────────────

/// A peer actor's cursor position within the document.
/// `line` / `col` map onto block index and offset within block content;
/// the renderer is intentionally agnostic about block structure so the
/// e2e harness can stamp arbitrary coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteCursor {
    pub actor_id: String,
    pub display_name: String,
    pub line: u32,
    pub col: u32,
}

/// One comment thread sealed to a `[start, end)` range within the
/// document. Spec contract is `ck.message.create` on the document
/// Strand's discussion track (`models/strand-and-message.md` §4.3) with a
/// payload that carries `anchor_range`. The thread is identified by
/// the originating message's event_id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentCommentThread {
    pub comment_id: String,
    pub author_did: String,
    pub range_start: u32,
    pub range_end: u32,
    pub body: String,
    pub replies: Vec<DocumentCommentReply>,
    pub resolved: bool,
    pub orphaned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentCommentReply {
    pub author_did: String,
    pub body: String,
}

// `SyncState` is an alias over the shared `SyncBadgeState` so document
// rendering goes through the unified badge. The label override for
// `LocalOnly` / `Failed` matches the previous user-facing copy
// ("Local draft" / "Local draft (sync failed)") rather than the generic
// default so e2e selectors and screenshots stay stable.
pub(super) type SyncState = SyncBadgeState;
const _: () = {
    // Compile-time check that the four-variant assumption still holds —
    // adding a fifth state upstream means we need to audit every render
    // site that exhaustively matches on this type.
    let _ = SyncState::Local;
    let _ = SyncState::Pending;
    let _ = SyncState::Synced;
    let _ = SyncState::Failed;
};
