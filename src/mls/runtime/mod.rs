//! Shared MLS runtime helpers.
//!
//! Normal Realm/Circle usage wraps local MLS checkpoints with an
//! account-scoped secret. The runtime exposes typed readiness errors when a
//! device has not yet received a Welcome delivery for a scope.
//!
//! This module is split by responsibility into:
//!   - [`secret`]: account- and device-scoped MLS secret management, the
//!     KeyPackage identity / inventory slots, and the device HPKE keypair;
//!   - [`backup`]: MLS epoch floors and key-backup envelope selection;
//!   - [`artifact_consumer`]: installing accepted MLS transitions and Welcome
//!     deliveries into this device's provider state;
//!   - [`genesis`]: creator initial-group setup and the `ak.mls.genesis` payload;
//!   - [`commit`]: the group-bound half of the self-preservation /
//!     forced-epoch-advance commits (the policy decision itself is
//!     `garth::mls::self_preservation`);
//!   - [`message`]: application-payload encrypt / decrypt, AAD, and mention
//!     routing-key derivation;
//!   - [`reaction`]: E2EE reaction sealing and routing-tag derivation.
//!
//! Every previously-public item is re-exported here so external paths such as
//! `crate::mls::runtime::X` keep resolving identically.

mod artifact_consumer;
mod backup;
mod commit;
mod genesis;
mod message;
mod reaction;
mod secret;

#[cfg(test)]
mod tests;

pub(crate) use artifact_consumer::*;
pub use backup::*;
pub use commit::*;
// Committer policy: host-neutral, owned by garth.
pub use garth::mls::self_preservation::{
    SELF_PRESERVATION_JITTER_SLOTS, SELF_PRESERVATION_MAX_EPOCH_AGE_DAYS,
    SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES, idle_self_update_jitter_passed,
    should_force_epoch_advance,
};
// Typed MLS readiness status / error surface: host-neutral, owned by garth.
pub use garth::mls::status::{MlsRuntimeError, MlsRuntimeStatus};

fn reject_retired_minimal_metadata_realm(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
) -> Result<(), MlsRuntimeError> {
    if state_store.realm_projection_has_retired_minimal_metadata_marker(realm_id) {
        return Err(MlsRuntimeError::Identity(
            "retired minimal-metadata Realm marker cannot authorize MLS operations".to_owned(),
        ));
    }
    Ok(())
}
pub use genesis::*;
pub use message::*;
pub use reaction::*;
pub use secret::*;
