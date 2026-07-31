//! Shared MLS runtime helpers.
//!
//! Normal Realm/Kanban usage uses an account-scoped secret to wrap local MLS
//! snapshots. The runtime exposes typed readiness errors when a device has not
//! yet received a Welcome or restored an MLS-history backup.
//!
//! This module is split by responsibility into:
//!   - [`errors`]: typed status / error surface;
//!   - [`secret`]: account- and device-scoped snapshot-secret management;
//!   - [`backup`]: MLS-history backup encode / decode / restore;
//!   - [`genesis`]: creator initial-group setup and `ak.mls.genesis` payload;
//!   - [`commit`]: §5.6 self-preservation / forced-epoch-advance commits;
//!   - [`mention`]: §4.5 E2EE mention routing-key derivation;
//!   - [`message`]: welcome apply, application-payload encrypt / decrypt, AAD;
//!   - [`reaction`]: §2.9 E2EE reaction sealing and routing-tag derivation.
//!
//! Every previously-public item is re-exported here so external paths such as
//! `crate::mls::runtime::X` keep resolving identically.

mod backup;
mod commit;
mod errors;
mod genesis;
mod mention;
mod message;
mod reaction;
mod secret;

#[cfg(test)]
mod tests;

pub use backup::*;
pub use commit::*;
pub use errors::*;
pub use genesis::*;
pub use mention::*;
pub use message::*;
pub use reaction::*;
pub use secret::*;
