//! MLS (Messaging Layer Security) integration for inkson.
//!
//! Grouped from the former top-level MLS governance and persistence files.
//! MIMI protocol calls live in `crate::transport::mls`, which uses the shared SDK
//! request/response types directly.

pub(crate) mod accepted_artifact;
pub mod account_recovery;
pub(crate) mod admission;
/// `epoch_update_required` repair: advance the MLS epoch so the Security Frontier
/// covers the governance Seals a paused scope is missing.
pub(crate) mod coverage_liveness;
/// Replayable creator-side MLS bootstrap (accepted Seal view → verified
/// governance proof → epoch-0 snapshot → `ak.mls.genesis`).
pub(crate) mod creator_bootstrap;
pub(crate) mod direct_binding;
pub(crate) mod governance_proof;
/// MLS group-lifecycle event builders (`ak.mls.genesis` / `ak.mls.commit`)
/// with governance bindings; moved out of `views/kanban`.
pub(crate) mod group_events;
pub mod persistence;
pub(crate) mod roster_install;
pub mod runtime;
/// The durable MLS send gate of one effective scope.
pub(crate) mod send_gate;
/// The `keypackages/consume` a joined Welcome owes once it is durable.
pub mod welcome_consume;
pub(crate) mod welcome_delivery;
