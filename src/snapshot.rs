//! Snapshot bootstrap helpers — verify chunk integrity against the SDK's
//! Merkle-rooted snapshot model before trusting it.
//!
//! Spec: `conformance/snapshot-schema.md`. The Principal Server advertises
//! `/sync/snapshot-head` plus chunk URLs; the client MUST verify the manifest's
//! Merkle root and each chunk's content hash before applying. This module is a
//! thin orchestration layer that delegates verification to
//! `contrix_sdk::verify_snapshot_chunks`.

use contrix_sdk::{ReducerSnapshotManifest, verify_snapshot_chunks};

/// Outcome of a snapshot verification round.
#[derive(Debug)]
pub enum SnapshotVerifyResult {
    /// All chunks matched their declared content hash and the manifest's
    /// `merkle_root` reconciled with the recomputed root.
    Verified {
        manifest_chunks: usize,
        total_bytes: usize,
    },
    /// One or more chunks failed verification. The error message names the
    /// first offending chunk for diagnostics.
    Mismatch(String),
}

/// Verify a snapshot manifest against the chunks fetched from the Principal
/// Server. Chunk bytes are passed in manifest order (`index = 0..N`).
///
/// Returns [`SnapshotVerifyResult::Mismatch`] if any chunk content hash does
/// not match its manifest entry, or if the recomputed root diverges from the
/// declared root.
pub fn verify_snapshot(
    manifest: &ReducerSnapshotManifest,
    chunks: impl IntoIterator<Item = Vec<u8>>,
) -> SnapshotVerifyResult {
    let chunk_vec: Vec<Vec<u8>> = chunks.into_iter().collect();
    let total_bytes: usize = chunk_vec.iter().map(|b| b.len()).sum();
    let manifest_chunks = chunk_vec.len();

    match verify_snapshot_chunks(manifest, chunk_vec.iter().map(|b| b.as_slice())) {
        Ok(()) => SnapshotVerifyResult::Verified {
            manifest_chunks,
            total_bytes,
        },
        Err(e) => SnapshotVerifyResult::Mismatch(format!("{e:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use contrix_sdk::{SnapshotChunkManifest, canonical, identifiers::SpaceId};

    fn empty_manifest() -> ReducerSnapshotManifest {
        ReducerSnapshotManifest {
            schema: contrix_sdk::REDUCER_SNAPSHOT_SCHEMA.to_owned(),
            reducer_profile: contrix_sdk::REDUCER_SNAPSHOT_PROFILE.to_owned(),
            space_id: SpaceId::new("cx:space:01964137-0000-7000-8000-000000000000".to_owned())
                .unwrap(),
            space_version: "0".to_owned(),
            frontier: Vec::new(),
            state_hash: canonical::sha256_digest(b"empty"),
            merkle_root: canonical::sha256_digest(b"empty"),
            chunk_count: 0,
            chunks: Vec::new(),
            created_at: Utc::now(),
            signatures: Vec::new(),
        }
    }

    #[test]
    fn empty_manifest_verifies_with_no_chunks() {
        let manifest = empty_manifest();
        match verify_snapshot(&manifest, std::iter::empty()) {
            SnapshotVerifyResult::Verified {
                manifest_chunks,
                total_bytes,
            } => {
                assert_eq!(manifest_chunks, 0);
                assert_eq!(total_bytes, 0);
            }
            SnapshotVerifyResult::Mismatch(e) => panic!("empty manifest failed: {e}"),
        }
    }

    #[test]
    fn mismatched_chunk_bytes_are_rejected() {
        let bytes = b"hello world".to_vec();
        let chunk = SnapshotChunkManifest {
            index: 0,
            digest: canonical::sha256_digest(b"different"),
            byte_len: bytes.len(),
        };
        let mut manifest = empty_manifest();
        manifest.chunk_count = 1;
        manifest.chunks = vec![chunk];

        match verify_snapshot(&manifest, std::iter::once(bytes)) {
            SnapshotVerifyResult::Mismatch(_) => {}
            SnapshotVerifyResult::Verified { .. } => {
                panic!("verifier accepted a chunk whose bytes do not match the declared digest")
            }
        }
    }

    #[test]
    fn matching_chunk_bytes_pass() {
        let bytes = b"hello world".to_vec();
        let chunk = SnapshotChunkManifest {
            index: 0,
            digest: canonical::sha256_digest(&bytes),
            byte_len: bytes.len(),
        };
        let mut manifest = empty_manifest();
        manifest.chunk_count = 1;
        manifest.chunks = vec![chunk];

        match verify_snapshot(&manifest, std::iter::once(bytes)) {
            SnapshotVerifyResult::Verified {
                manifest_chunks,
                total_bytes,
            } => {
                assert_eq!(manifest_chunks, 1);
                assert_eq!(total_bytes, 11);
            }
            SnapshotVerifyResult::Mismatch(e) => panic!("verifier rejected a valid chunk: {e}"),
        }
    }

    #[test]
    fn chunk_count_mismatch_is_rejected() {
        let mut manifest = empty_manifest();
        manifest.chunk_count = 1;
        manifest.chunks = vec![SnapshotChunkManifest {
            index: 0,
            digest: canonical::sha256_digest(b"x"),
            byte_len: 1,
        }];

        // Supplying zero chunks against a one-chunk manifest must fail.
        match verify_snapshot(&manifest, std::iter::empty()) {
            SnapshotVerifyResult::Mismatch(_) => {}
            SnapshotVerifyResult::Verified { .. } => {
                panic!("verifier accepted zero chunks against a one-chunk manifest")
            }
        }
    }
}
