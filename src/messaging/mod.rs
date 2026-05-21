//! G3.Y2 — messaging UI scaffolding shared by `views::chat` and
//! `views::timeline`.
//!
//! This module hosts the *client-side* state machines and serialisers
//! for the advanced messaging surfaces (mentions, polls, typing,
//! presence, read receipts, discussion promote) so the chat view file
//! stays focused on rendering. Most of the soland-side semantics for
//! these features are deferred (see `// TODO(G3.Y2-followup): ...`
//! markers); the goal here is to ship the UI surface so the cotest
//! e2e suite can assert against stable testids.
//!
//! Submodules:
//! * [`polls`] — poll draft + result-tally state used by the composer
//!   and the timeline poll card.
//! * [`mentions`] — @mention picker state + sidecar hash helper for
//!   E2EE-aware mention routing.
//! * [`discussion_promote`] — "promote this Flow's discussion into a
//!   child Space" UI state.

pub mod discussion_promote;
pub mod mentions;
pub mod polls;
