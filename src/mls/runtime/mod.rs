//! Shared MLS runtime helpers.
//!
//! Normal Realm/Kanban usage uses an account-scoped secret to wrap local MLS
//! snapshots. The runtime exposes typed readiness errors when a device has not
//! yet received a Welcome or restored an MLS-history backup.
//!
//! This module is split by responsibility into:
//!   - [`secret`]: the host half of snapshot-secret management (the protocol half is
//!     `garth::mls::device_secret`);
//!   - [`backup`]: MLS-history backup encode / decode / restore;
//!   - [`genesis`]: creator initial-group setup and `ak.mls.genesis` payload;
//!   - [`commit`]: the group-bound half of the §5.6 self-preservation / forced-epoch-advance
//!     commits (the policy decision itself is `garth::mls::self_preservation`);
//!   - [`mention`]: §4.5 E2EE mention routing-key derivation;
//!   - [`message`]: welcome apply, application-payload encrypt / decrypt, AAD;
//!   - [`reaction`]: §2.9 E2EE reaction sealing and routing-tag derivation.
//!
//! Every previously-public item is re-exported here so external paths such as
//! `crate::mls::runtime::X` keep resolving identically.

mod artifact_consumer;
mod backup;
mod commit;
mod genesis;
mod history_candidate_consumer;
mod message;
mod reaction;
mod secret;

#[cfg(test)]
mod tests;

pub(crate) use artifact_consumer::*;
pub use backup::*;
pub use commit::*;
// §2.9 / §5.6 committer policy: host-neutral, owned by garth.
pub use garth::mls::self_preservation::{
    SELF_PRESERVATION_JITTER_SLOTS, SELF_PRESERVATION_MAX_EPOCH_AGE_DAYS,
    SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES, idle_self_update_jitter_passed,
    should_force_epoch_advance,
};
// Typed MLS readiness status / error surface: host-neutral, owned by garth.
pub use garth::mls::status::{MlsRuntimeError, MlsRuntimeStatus};
pub use genesis::*;
pub(crate) use history_candidate_consumer::*;
pub use message::*;
pub use reaction::*;
pub use secret::*;
