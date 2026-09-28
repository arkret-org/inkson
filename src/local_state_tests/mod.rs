//! Structural split of the former monolithic `local_state_tests.rs`.
//!
//! This module is mounted from `local_state.rs` as the private `tests`
//! submodule of `local_state` (via `#[cfg(test)] #[path = ...] mod tests;`),
//! so `super` here still resolves to the `local_state` module. The
//! `pub(super) use super::*;` below re-exports every visible `local_state`
//! item (its public types and the `pub(crate)` `storage_util` helpers)
//! down to the topic submodules. Private fields of `LocalStateStore`
//! (`cached`, `path`) remain reachable because private visibility extends to
//! the whole module subtree, so the grandchild test modules can touch them
//! directly.

use std::time::{SystemTime, UNIX_EPOCH};

pub(super) use super::*;

#[cfg(not(target_arch = "wasm32"))]
mod account_blob_capacity;
mod identity;
mod mls_local_checkpoint;
mod move_submission;
mod presence;
mod private_plaintext;
mod projections;
mod read_receipt;
mod remark;
mod store_persist;
mod sync_states;

// ── Shared test helpers (used by multiple topic submodules) ─

pub(super) fn test_authority(principal: &str) -> arkret_sdk::AccountId {
    test_authority_at_server(principal, "ak:did_core:web:test-server.example")
}

pub(super) fn test_authority_at_server(principal: &str, station: &str) -> arkret_sdk::AccountId {
    crate::test_support::authority_at_station(principal, station)
}

pub(super) fn test_profile_id(authority: &arkret_sdk::AccountId) -> String {
    format!(
        "ak:profile:{}",
        crate::secure_key_store::account_id_storage_digest(authority).unwrap()
    )
}

pub(super) fn test_device_id() -> arkret_sdk::DeviceId {
    crate::test_support::device_id("ak:device:01964137-0000-7000-8000-000000000001")
}

pub(super) fn test_account_context(did: &arkret_sdk::Did) -> crate::config::ActiveAccountContext {
    let authority = test_authority(did.as_str());
    test_account_context_for_authority(did, authority)
}

pub(super) fn test_account_context_for_authority(
    did: &arkret_sdk::Did,
    authority: arkret_sdk::AccountId,
) -> crate::config::ActiveAccountContext {
    crate::test_support::AccountFixture::new(did.as_str())
        .station(authority.station_id.as_str())
        .profile_id(test_profile_id(&authority))
        .resolution("test-head", "test-version", "test-event")
        .updated_at("2026-08-22T00:00:00Z".parse().unwrap())
        .server_url("https://test-server.example")
        .build()
}

impl LocalStateStore {
    pub(crate) fn switch_test_account(&mut self, principal: &str) -> bool {
        if principal == crate::state::ANONYMOUS_ACCOUNT_NAMESPACE {
            return false;
        }
        let did = arkret_sdk::Did::new(principal.to_owned()).unwrap();
        let account = test_account_context(&did);
        let was_known = self
            .known_profile_id_for_authority(&account.authority)
            .is_some();
        self.switch_active_account(&account).unwrap();
        !was_known
    }

    pub(super) fn primary_handle_for_test_principal(&self, principal: &str) -> Option<String> {
        self.primary_handle_for_principal_id(principal)
    }

    pub(super) fn begin_test_pending_login(&mut self, device_id: &str, dpop_jkt: Option<&str>) {
        let device_id = arkret_sdk::DeviceId::new(device_id.to_owned()).unwrap();
        self.begin_pending_login(&device_id, dpop_jkt);
    }
}

pub(super) fn temp_state_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("inkson-state-{name}-{stamp}.json"))
}

/// A commit-stream head on a Realm's own stream, for tests that need a
/// per-stream cursor rather than a Realm-global position (there is none).
pub(super) fn realm_stream_head(realm_id: &str, position: u64) -> arkret_wire::CommitStreamHead {
    arkret_wire::CommitStreamHead {
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
        },
        stream_position: position,
        commit_id: arkret_wire::RealmCommitId::from_digest([position as u8; 32]),
    }
}
