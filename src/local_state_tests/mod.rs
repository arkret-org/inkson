//! Structural split of the former monolithic `local_state_tests.rs`.
//!
//! This module is mounted from `local_state.rs` as the private `tests`
//! submodule of `local_state` (via `#[cfg(test)] #[path = ...] mod tests;`),
//! so `super` here still resolves to the `local_state` module. The
//! `pub(super) use super::*;` below re-exports every visible `local_state`
//! item (its public types, the `pub use seal_view::*` re-exports, and the
//! `pub(crate)` `storage_util` helpers such as `xor_encrypt`/`xor_decrypt`)
//! down to the topic submodules. Private fields of `LocalStateStore`
//! (`cached`, `path`) remain reachable because private visibility extends to
//! the whole module subtree, so the grandchild test modules can touch them
//! directly.

use std::time::{SystemTime, UNIX_EPOCH};

pub(super) use super::*;

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

pub(super) fn temp_state_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("yougen-state-{name}-{stamp}.json"))
}

pub(super) fn snapshot_event_id(suffix: &str) -> cokret_sdk::EventId {
    cokret_sdk::EventId::new(format!("ck:event:01904100-0000-7000-8000-{suffix}")).unwrap()
}

pub(super) fn snapshot_hash(seed: u8) -> cokret_sdk::Hash {
    cokret_sdk::Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

pub(super) fn snapshot_manifest_for_items(
    items: Vec<cokret_sdk::SnapshotMaterializedItem>,
) -> (
    cokret_sdk::SnapshotManifest,
    Vec<cokret_sdk::SnapshotChunkPayload>,
) {
    let snapshot_id =
        cokret_sdk::SnapshotId::new("ck:snapshot:01904100-0000-7000-8000-0000000000aa").unwrap();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000000aa").unwrap();
    let service_did = cokret_sdk::Did::new("did:web:server.example").unwrap();
    let state_digest = cokret_sdk::state_digest_from_items(&items).unwrap();
    let built = cokret_sdk::build_snapshot_chunks(
        &snapshot_id,
        cokret_sdk::SNAPSHOT_REDUCER_PROFILE_V1,
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
    let mut manifest = cokret_sdk::SnapshotManifest {
        id: snapshot_id,
        realm_id,
        reducer_profile: cokret_sdk::SNAPSHOT_REDUCER_PROFILE_V1.to_owned(),
        schema_profile_refs: vec!["ck.profile.core_event_store.v1".to_owned()],
        state_digest,
        frontier: cokret_sdk::SnapshotFrontier {
            event_ids: vec![snapshot_event_id("0000000000a2")],
            timeline_hlc: cokret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        },
        event_set_commitment: cokret_sdk::EventSetCommitment {
            algorithm: cokret_sdk::EventSetCommitmentAlgorithm::MerkleEventSetV1,
            root: snapshot_hash(9),
            covered_event_count: 2,
            covered_seals: vec![snapshot_event_id("0000000000a2")],
            actor_seq_ranges: Vec::new(),
        },
        chunks,
        security_class: cokret_sdk::SnapshotSecurityClass::Standard,
        verification_hints: None,
        created_by: service_did.clone(),
        created_at,
        authority_binding: cokret_sdk::AuthorityBinding {
            issuer: service_did,
            authority_kind: cokret_sdk::SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
            auth_state_digest: snapshot_hash(1),
            auth_frontier: vec![snapshot_event_id("0000000000a2")],
            checked_at: created_at,
            witness_attestations: Vec::new(),
        },
        signature: cokret_sdk::DetachedJwsProof::eddsa(
            "did:web:server.example#snapshot".to_owned(),
            snapshot_hash(2),
            created_at,
            "header..signature".to_owned(),
        ),
    };
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    (manifest, chunk_payloads)
}
