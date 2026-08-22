//! MLS snapshot epoch floors.
//!
//! Same-endpoint active snapshots remain local device state. Portable human
//! history uses authorized `history_secret_ranges` material and is not
//! implemented in this module.

pub fn mls_restore_epoch_floor(state_store: &crate::state::LocalStateStore, realm_id: &str) -> u64 {
    let seal_epoch = seal_view_epoch_floor(state_store, realm_id);
    let local_epoch = state_store
        .mls_snapshot_for(realm_id)
        .map(|snapshot| snapshot.epoch)
        .unwrap_or(0);
    seal_epoch.max(local_epoch)
}

/// COR-04: the Realm's Seal-view MLS epoch, used as the `current_epoch_floor`
/// the on-disk snapshot write paths (commit / encrypt / reaction-send) pass to
/// [`crate::mls::persistence::restore_envelope`].
///
/// Unlike [`mls_restore_epoch_floor`] this does NOT `max` in the local
/// snapshot's own epoch: at a write site the snapshot being restored *is* the
/// local snapshot, so folding its epoch back in would make
/// `decrypt_with_epoch_check` a tautology that can never fire. Returning only
/// the independently-sourced Seal-view epoch lets `OutdatedSnapshot` actually
/// trip when a concurrently-overwritten / rolled-back local snapshot has fallen
/// behind the Seal lattice (`persistence.rs` anti-stale-fork design, §2.9).
/// When no Seal view is known yet (`None`) the floor is `0` (no check), matching
/// the first-boot rehydrate semantics.
pub fn seal_view_epoch_floor(state_store: &crate::state::LocalStateStore, realm_id: &str) -> u64 {
    state_store
        .seal_view_for_realm(realm_id)
        .mls_epoch
        .unwrap_or(0)
}
