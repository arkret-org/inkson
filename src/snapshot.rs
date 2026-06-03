//! Snapshot bootstrap helpers — verify chunk integrity against the SDK's
//! Merkle-rooted snapshot model before trusting it.
//!
//! Spec: `conformance/snapshot-schema.md`. The Principal Server advertises
//! `/sync/snapshot-head` plus chunk URLs; the client MUST verify the manifest's
//! Merkle root and each chunk's content hash before applying. This module is a
//! thin orchestration layer that delegates verification to
//! `contrix_sdk::verify_snapshot_chunks`.

use contrix_sdk::{ReducerSnapshotManifest, verify_snapshot_chunks};

/// Round 4 (spec a77b995) — outcome of consuming a
/// [`contrix_sdk::SnapshotBootstrap`] envelope carried alongside a
/// `cx.events.query` response. The receiver validates the envelope's
/// structural fields (`signature`, `state_digest`, `snapshot_frontier`,
/// per-chunk digests) BEFORE applying any chunk bytes. Any failure
/// returns [`SnapshotBootstrapOutcome::FallBackFullSync`] so the
/// caller falls back to a full `/sync` rebuild rather than trust a
/// partially-validated snapshot.
///
/// The internal chunked-import path is still
/// `TODO(round4-snapshot-bootstrap-import)`. The wire shape MUST parse
/// here so producer / consumer services can negotiate the new envelope
/// shape; chunk-fetch + integrity-check + apply lives in the follow-up.
#[derive(Clone, Debug, PartialEq)]
pub enum SnapshotBootstrapOutcome {
    /// All envelope-level invariants held (signature present,
    /// state_digest non-empty, snapshot_frontier non-empty, every chunk
    /// has a digest + fetch_ref). The caller may proceed to the
    /// per-chunk fetch + verify step.
    AcceptedHeader {
        chunk_count: usize,
        state_digest: String,
    },
    /// Some structural invariant failed. The caller MUST drop the
    /// bootstrap envelope and fall back to a full sync.
    FallBackFullSync(String),
}

/// Round 4 — validate the structural fields of a
/// [`contrix_sdk::SnapshotBootstrap`] envelope. Returns
/// [`SnapshotBootstrapOutcome::AcceptedHeader`] only when every
/// required field is populated; any miss → fall back to full sync.
///
/// TODO(round4-snapshot-bootstrap-import): once the receiver gains the
/// chunked-import pipeline (per-chunk fetch + digest re-verify +
/// reducer apply), call this helper from the import entry point and
/// proceed to chunk fetching when accepted.
pub fn consume_snapshot_bootstrap(
    bootstrap: &contrix_sdk::SnapshotBootstrap,
) -> SnapshotBootstrapOutcome {
    if bootstrap.signature.alg.trim().is_empty()
        || bootstrap.signature.verification_method.trim().is_empty()
        || bootstrap.signature.jws.trim().is_empty()
        || bootstrap
            .signature
            .payload_digest
            .as_str()
            .trim()
            .is_empty()
    {
        return SnapshotBootstrapOutcome::FallBackFullSync(
            "snapshot_bootstrap.signature is incomplete".to_owned(),
        );
    }
    if let Err(err) = bootstrap.validate_signature_binding() {
        return SnapshotBootstrapOutcome::FallBackFullSync(format!(
            "snapshot_bootstrap.signature binding failed: {err}"
        ));
    }
    if bootstrap.state_digest.as_str().trim().is_empty() {
        return SnapshotBootstrapOutcome::FallBackFullSync(
            "snapshot_bootstrap.state_digest is empty".to_owned(),
        );
    }
    if bootstrap.snapshot_frontier.is_empty() {
        return SnapshotBootstrapOutcome::FallBackFullSync(
            "snapshot_bootstrap.snapshot_frontier is empty".to_owned(),
        );
    }
    for (index, chunk) in bootstrap.chunks.iter().enumerate() {
        if chunk.chunk_id.trim().is_empty() {
            return SnapshotBootstrapOutcome::FallBackFullSync(format!(
                "snapshot_bootstrap.chunks[{index}].chunk_id is empty"
            ));
        }
        if chunk.digest.as_str().trim().is_empty() {
            return SnapshotBootstrapOutcome::FallBackFullSync(format!(
                "snapshot_bootstrap.chunks[{index}].digest is empty"
            ));
        }
        if chunk.fetch_ref.trim().is_empty() {
            return SnapshotBootstrapOutcome::FallBackFullSync(format!(
                "snapshot_bootstrap.chunks[{index}].fetch_ref is empty"
            ));
        }
    }
    SnapshotBootstrapOutcome::AcceptedHeader {
        chunk_count: bootstrap.chunks.len(),
        state_digest: bootstrap.state_digest.as_str().to_owned(),
    }
}

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
    use chrono::Utc;
    use contrix_sdk::identifiers::SpaceId;
    use contrix_sdk::{
        EventId, Hash, SnapshotBootstrap, SnapshotBootstrapChunk, SnapshotBootstrapSignature,
        SnapshotChunkManifest, canonical,
    };

    use super::*;

    fn empty_manifest() -> ReducerSnapshotManifest {
        ReducerSnapshotManifest {
            schema: contrix_sdk::REDUCER_SNAPSHOT_SCHEMA.to_owned(),
            reducer_profile: contrix_sdk::REDUCER_SNAPSHOT_PROFILE.to_owned(),
            space_id: SpaceId::new("ck:space:01964137-0000-7000-8000-000000000000".to_owned())
                .unwrap(),
            space_version: "0".to_owned(),
            frontier: Vec::new(),
            state_digest: canonical::sha256_digest(b"empty"),
            merkle_root: canonical::sha256_digest(b"empty"),
            chunk_count: 0,
            chunks: Vec::new(),
            created_at: Utc::now(),
            signatures: Vec::new(),
        }
    }

    fn test_hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn valid_bootstrap() -> SnapshotBootstrap {
        let mut bootstrap = SnapshotBootstrap {
            signature: SnapshotBootstrapSignature {
                alg: "EdDSA".to_owned(),
                verification_method: "did:web:alice.example#device".to_owned(),
                payload_digest: test_hash('0'),
                created_at: Utc::now(),
                jws: "header..signature".to_owned(),
            },
            state_digest: test_hash('1'),
            snapshot_frontier: vec![
                EventId::new("ck:event:01904100-0000-7000-8000-000000000001".to_owned()).unwrap(),
            ],
            chunks: vec![SnapshotBootstrapChunk {
                chunk_id: "chunk-0".to_owned(),
                digest: test_hash('2'),
                size_bytes: 128,
                fetch_ref: "ck:blob:snapshot-chunk-0".to_owned(),
            }],
        };
        bootstrap.signature.payload_digest = bootstrap.signing_payload_digest().unwrap();
        bootstrap
    }

    #[test]
    fn snapshot_bootstrap_header_accepts_bound_signature() {
        let outcome = consume_snapshot_bootstrap(&valid_bootstrap());
        assert_eq!(
            outcome,
            SnapshotBootstrapOutcome::AcceptedHeader {
                chunk_count: 1,
                state_digest: test_hash('1').as_str().to_owned(),
            }
        );
    }

    #[test]
    fn snapshot_bootstrap_header_rejects_partial_signature() {
        let mut bootstrap = valid_bootstrap();
        bootstrap.signature.jws.clear();
        let outcome = consume_snapshot_bootstrap(&bootstrap);
        assert!(matches!(
            outcome,
            SnapshotBootstrapOutcome::FallBackFullSync(reason)
                if reason.contains("signature is incomplete")
        ));
    }

    #[test]
    fn snapshot_bootstrap_header_rejects_signature_digest_drift() {
        let mut bootstrap = valid_bootstrap();
        bootstrap.signature.payload_digest = test_hash('3');
        let outcome = consume_snapshot_bootstrap(&bootstrap);
        assert!(matches!(
            outcome,
            SnapshotBootstrapOutcome::FallBackFullSync(reason)
                if reason.contains("signature binding failed")
        ));
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
