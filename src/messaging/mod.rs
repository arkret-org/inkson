//! G3.Y2 — messaging UI scaffolding shared by `views::chat` and
//! `crate::state::projection`.
//!
//! This module hosts the *client-side* state machines and serialisers
//! for the advanced messaging surfaces (mentions, polls, typing,
//! presence, read receipts, discussion promote) so the chat view file
//! stays focused on rendering. Polls are a default local UI surface; discussion
//! promote remains hidden from the default local UI behind
//! `experimental-discussion-promote`.
//!
//! Submodules:
//! * [`polls`] — poll draft + result-tally state used by the composer and chat poll card.
//! * [`mentions`] — @mention picker state + sidecar hash helper for E2EE-aware mention routing.
//! * [`discussion_promote`] — "promote this Strand's discussion into a Circle-scoped Strand" UI
//!   state.

pub mod discussion_promote;
pub mod mentions;
pub mod polls;
