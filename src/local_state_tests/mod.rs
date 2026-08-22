//! Structural split of the former monolithic `local_state_tests.rs`.
//!
//! This module is mounted from `local_state.rs` as the private `tests`
//! submodule of `local_state` (via `#[cfg(test)] #[path = ...] mod tests;`),
//! so `super` here still resolves to the `local_state` module. The
//! `pub(super) use super::*;` below re-exports every visible `local_state`
//! item (its public types, the `pub use seal_view::*` re-exports, and the
//! `pub(crate)` `storage_util` helpers such as
//! `obfuscate_nonsensitive`/`deobfuscate_nonsensitive`)
//! down to the topic submodules. Private fields of `LocalStateStore`
//! (`cached`, `path`) remain reachable because private visibility extends to
//! the whole module subtree, so the grandchild test modules can touch them
//! directly.

use std::time::{SystemTime, UNIX_EPOCH};

pub(super) use super::*;

mod history_candidates;
mod identity;
mod mls_snapshot;
mod move_submission;
mod presence;
mod private_plaintext;
mod projections;
mod read_receipt;
mod remark;
mod seal_view;
mod store_persist;
mod sync_states;

// ── Shared test helpers (used by multiple topic submodules) ─

pub(super) fn test_authority(principal: &str) -> arkret_sdk::PrincipalAuthorityKey {
    test_authority_at_server(principal, "ak:did_core:web:test-server.example")
}

pub(super) fn test_authority_at_server(
    principal: &str,
    principal_server: &str,
) -> arkret_sdk::PrincipalAuthorityKey {
    let principal_id = arkret_sdk::DidCoreId::new(principal.to_owned()).unwrap_or_else(|_| {
        let full_id = arkret_sdk::DidFullId::new(principal.to_owned()).expect("full principal DID");
        arkret_sdk::project_full_id_to_core_id(&full_id).expect("principal core projection")
    });
    arkret_sdk::PrincipalAuthorityKey::new(
        principal_id,
        arkret_sdk::DidCoreId::new(principal_server.to_owned()).unwrap(),
    )
}

pub(super) fn test_profile_id(authority: &arkret_sdk::PrincipalAuthorityKey) -> String {
    format!(
        "ak:profile:{}",
        crate::secure_key_store::principal_authority_storage_digest(authority).unwrap()
    )
}

pub(super) fn test_device_id() -> arkret_sdk::DeviceId {
    arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned()).unwrap()
}

pub(super) fn test_account_context(
    full_id: &arkret_sdk::DidFullId,
) -> crate::config::ActiveAccountContext {
    let authority = test_authority(full_id.as_str());
    test_account_context_for_authority(full_id, authority)
}

pub(super) fn test_account_context_for_authority(
    full_id: &arkret_sdk::DidFullId,
    authority: arkret_sdk::PrincipalAuthorityKey,
) -> crate::config::ActiveAccountContext {
    crate::config::ActiveAccountContext::new(
        test_profile_id(&authority),
        authority,
        arkret_sdk::PrincipalResolutionProjection {
            full_id: full_id.clone(),
            method_history_head: "test-head".to_owned(),
            version_id: "test-version".to_owned(),
            resolution_event_ref: "test-event".to_owned(),
            updated_at: "2026-08-22T00:00:00Z".parse().unwrap(),
        },
        test_device_id(),
        url::Url::parse("https://test-server.example").unwrap(),
    )
    .unwrap()
}

impl LocalStateStore {
    pub(crate) fn switch_test_account(&mut self, principal: &str) -> bool {
        if principal == crate::state::ANONYMOUS_ACCOUNT_NAMESPACE {
            return false;
        }
        let full_id = arkret_sdk::DidFullId::new(principal.to_owned()).unwrap();
        let account = test_account_context(&full_id);
        let was_known = self
            .known_profile_id_for_authority(&account.authority)
            .is_some();
        self.switch_active_account(&account).unwrap();
        !was_known
    }

    pub(super) fn last_selected_test_principal_id(&self) -> Option<String> {
        let root = self.read_root();
        root.active_profile_id
            .as_deref()
            .and_then(|profile_id| root.authority_for_profile(profile_id))
            .map(|authority| authority.principal_id.to_string())
    }

    pub(super) fn known_test_principal_ids(&self) -> Vec<String> {
        self.known_principal_ids()
    }

    pub(super) fn primary_handle_for_test_principal(&self, principal: &str) -> Option<String> {
        self.primary_handle_for_did(principal)
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

pub(super) fn snapshot_event_id(suffix: &str) -> arkret_sdk::EventId {
    let seed = u8::from_str_radix(&suffix[suffix.len() - 2..], 16).unwrap();
    arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [seed; 32])
}

pub(super) fn snapshot_hash(seed: u8) -> arkret_sdk::Hash {
    arkret_sdk::Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

pub(super) fn snapshot_manifest_for_items(
    items: Vec<arkret_sdk::SnapshotMaterializedItem>,
) -> (
    arkret_sdk::SnapshotManifest,
    Vec<arkret_sdk::SnapshotChunkPayload>,
) {
    let snapshot_id =
        arkret_sdk::SnapshotId::new("ak:snapshot:01904100-0000-7000-8000-0000000000aa").unwrap();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap();
    let service_id = crate::mls_api_helpers::principal_core_id("did:web:server.example").unwrap();
    let state_digest = arkret_sdk::state_digest_from_items(&items).unwrap();
    let built = arkret_sdk::build_snapshot_chunks(
        &snapshot_id,
        arkret_sdk::CORE_REDUCER_PROFILE,
        items,
        4096,
    )
    .unwrap();
    let chunk_payloads = built
        .iter()
        .map(|chunk| chunk.payload.clone())
        .collect::<Vec<_>>();
    let chunks = built
        .into_iter()
        .map(|chunk| chunk.descriptor)
        .collect::<Vec<_>>();
    let created_at = Utc::now();
    let mut manifest = arkret_sdk::SnapshotManifest {
        id: snapshot_id,
        realm_id,
        reducer_profile: arkret_sdk::CORE_REDUCER_PROFILE.to_owned(),
        schema_profile_refs: vec!["ak.profile.core_event_store.v1".to_owned()],
        state_digest,
        frontier: arkret_sdk::SnapshotFrontier {
            event_ids: vec![snapshot_event_id("0000000000a2")],
            timeline_hlc: arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        },
        event_set_commitment: arkret_sdk::EventSetCommitment {
            algorithm: arkret_sdk::EventSetCommitmentAlgorithm::MerkleEventSetV1,
            root: snapshot_hash(9),
            covered_event_count: 2,
            covered_event_ids: vec![snapshot_event_id("0000000000a2")],
            actor_seq_ranges: Vec::new(),
        },
        chunks,
        security_class: arkret_sdk::SnapshotSecurityClass::Standard,
        verification_hints: None,
        created_by: service_id.clone(),
        created_at,
        authority_binding: arkret_sdk::AuthorityBinding {
            issuer: service_id,
            authority_kind: arkret_sdk::SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
            auth_state_digest: snapshot_hash(1),
            auth_frontier: vec![snapshot_event_id("0000000000a2")],
            checked_at: created_at,
            witness_attestations: Vec::new(),
        },
        signature: arkret_sdk::DetachedJwsProof::ed25519(
            arkret_sdk::DidUrl::new("did:web:server.example#snapshot").unwrap(),
            snapshot_hash(2),
            created_at,
            "header..signature".to_owned(),
        ),
    };
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    (manifest, chunk_payloads)
}
