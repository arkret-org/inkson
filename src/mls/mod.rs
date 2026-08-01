//! MLS (Messaging Layer Security) integration for inkson.
//!
//! Grouped from the former top-level MLS governance and persistence files.
//! MIMI protocol calls live in `crate::transport::mls`, which uses the shared SDK
//! request/response types directly.

pub mod account_recovery;
pub(crate) mod admission;
/// `epoch_update_required` repair: advance the MLS epoch so `covered_seals_cell`
/// covers the governance Seals a paused scope is missing.
pub(crate) mod coverage_liveness;
/// Replayable creator-side MLS bootstrap (accepted Seal view → verified
/// governance proof → epoch-0 snapshot → `ak.mls.genesis`).
pub(crate) mod creator_bootstrap;
pub mod durability;
pub mod governance;
pub(crate) mod governance_proof;
/// MLS group-lifecycle event builders (`ak.mls.genesis` / `ak.mls.commit`)
/// with governance bindings; moved out of `views/kanban` (YGN-ARCH-01).
pub(crate) mod group_events;
pub mod persistence;
pub mod runtime;
pub mod secret_share;
