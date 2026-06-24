// Re-export the parent (`chat/mod.rs`) glob into this module AND down to the
// sub-files. `super` here is `chat/mod.rs`; `pub(crate) use super::*;` pulls in
// every name it brought via `use ...;` (Value, json!, MentionNode, WatchLevel,
// ClientLocalState, cokret_sdk, crate::* …) and re-exports them so each
// sub-file's own `use super::*;` (where their `super` is this module) resolves
// the same set of names. Rust does not propagate glob-imported names through a
// glob, so this explicit re-export is what keeps the children compiling.
pub(crate) use super::*;

mod agents;
mod events;
mod mentions;
mod operations;
mod outbox;
mod participants;
mod strands;
mod types;

// Re-export every sub-file's `pub(crate)` items so (a) sibling sub-files see
// each other through their `use super::*;`, and (b) `chat/mod.rs`'s
// `use model::*;` keeps resolving every name unchanged.
pub(crate) use agents::*;
pub(crate) use events::*;
pub(crate) use mentions::*;
pub(crate) use operations::*;
pub(crate) use outbox::*;
pub(crate) use participants::*;
pub(crate) use strands::*;
pub(crate) use types::*;

#[cfg(test)]
mod tests;
