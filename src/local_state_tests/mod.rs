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
    std::env::temp_dir().join(format!("inkson-state-{name}-{stamp}.json"))
}

pub(super) fn snapshot_event_id(suffix: &str) -> arkret_sdk::EventId {
    arkret_sdk::EventId::new(format!("ak:event:01904100-0000-7000-8000-{suffix}")).unwrap()
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000aa").unwrap();
    let service_id = arkret_sdk::Did::new("did:web:server.example").unwrap();
    let state_digest = arkret_sdk::state_digest_from_items(&items).unwrap();
    let built = arkret_sdk::build_snapshot_chunks(
        &snapshot_id,
        arkret_sdk::SNAPSHOT_REDUCER_PROFILE_V1,
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
        reducer_profile: arkret_sdk::SNAPSHOT_REDUCER_PROFILE_V1.to_owned(),
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
            covered_seals: vec![snapshot_event_id("0000000000a2")],
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
        signature: arkret_sdk::DetachedJwsProof::eddsa(
            "did:web:server.example#snapshot".to_owned(),
            snapshot_hash(2),
            created_at,
            "header..signature".to_owned(),
        ),
    };
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    (manifest, chunk_payloads)
}
