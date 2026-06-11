//! F-ANCHOR-WIT-1: client-side Seal witness-chain verification.
//!
//! Spec source: `sync/finality-and-consensus.md §3` — every accepted
//! Seal MUST carry a witness chain (a set of signatures from the
//! seal's declared signers) that the receiver re-verifies before
//! treating the post-state root as authoritative.
//!
//! Yougen currently consumes server-side seal responses
//! (`SignSealOutcome` from `api.rs`) as opaque envelopes — the
//! server publishes them, the client trusts the resulting state root.
//! That's fine for a single-node deployment but breaks the spec's
//! finality guarantee in federation / multi-notary scenarios: a
//! single dishonest notary could substitute a forged root unless
//! the client cross-checks the witness signatures.
//!
//! This module ships the typed verifier so any future wire path that
//! surfaces the witness chain (whether SDK-side or via an admin endpoint)
//! has a single source of truth for "is this seal finalised?". It is
//! deliberately self-contained: no I/O, no global state, no SDK calls.
//!
//! Signature verification itself is delegated to a [`SignatureVerifier`]
//! closure so callers can plug in whatever scheme the SDK upgrades to
//! (HMAC chain today, Ed25519 detached signatures tomorrow) without
//! touching this module.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::federation::TrustBundle;

/// One signer's contribution to the Seal witness chain. Mirrors the
/// minimal shape needed to verify finality without committing to a
/// specific signature algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealWitness {
    /// DID of the signer (e.g. `did:web:notary.example`). The
    /// receiver verifies this DID is pinned in the trust bundle for
    /// the active deployment.
    pub signer_did: String,
    /// Domain the signer is pinned under in the trust bundle. The
    /// pinned [`crate::federation::TrustBundle`] keys seals by
    /// domain — this lets the verifier resolve the matching seal
    /// without a second DID lookup. When the witness was issued by
    /// the local service this is the local domain.
    pub signer_domain: String,
    /// Opaque signature payload. The verifier closure decides how to
    /// validate it (HMAC chain / Ed25519 / ...).
    pub signature: String,
    /// Optional RFC 3339 timestamp the witness was issued at. Carried
    /// verbatim for audit; not part of the verification path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
}

/// Witness chain attached to a single Seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealWitnessChain {
    pub seal_id: String,
    pub post_state_root: String,
    /// Signers that contributed to this chain. Order is not
    /// semantically significant; duplicate signer DIDs are rejected.
    pub witnesses: Vec<SealWitness>,
    /// Minimum distinct trusted signers required for the chain to be
    /// considered finalised. `0` is rejected — a chain with no
    /// required signers couldn't fail.
    pub threshold_required: usize,
}

/// Errors surfaced by [`verify_seal_witness_chain`]. Each variant maps to
/// a specific spec-prescribed rejection reason so the caller can
/// surface a precise audit row rather than a generic "verification
/// failed".
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SealSealWitnessError {
    /// `threshold_required` was zero. A chain that can never fail
    /// proves nothing; reject up front.
    #[error("seal witness threshold_required must be > 0")]
    ThresholdMustBePositive,
    /// `witnesses` was empty. A chain with no signers can't satisfy
    /// any positive threshold.
    #[error("seal witness chain is empty")]
    NoWitnessesProvided,
    /// `seal_id` was empty. Spec requires every witness to bind to
    /// a concrete seal.
    #[error("seal witness chain has empty seal_id")]
    MissingSealId,
    /// Two witnesses had the same `signer_did`. The threshold counts
    /// **distinct** trusted signers; duplicates would inflate the
    /// count and let one notary satisfy threshold N alone.
    #[error("seal witness chain repeats signer {0}")]
    DuplicateSigner(String),
    /// A witness referred to a domain that isn't pinned in the trust
    /// bundle. The receiver cannot trust the signature without a
    /// pinned seal for that domain.
    #[error(
        "seal witness signer {signer_did} (domain {signer_domain}) is not pinned in the trust bundle"
    )]
    UnknownSigner {
        signer_did: String,
        signer_domain: String,
    },
    /// A witness's signature failed the [`SignatureVerifier`] check.
    #[error("seal witness signature from {signer_did} failed verification")]
    SignatureInvalid { signer_did: String },
    /// The total number of distinct trusted, signature-valid witnesses
    /// fell short of `threshold_required`.
    #[error("seal witness threshold not met: required {required}, present {present}")]
    ThresholdNotMet { required: usize, present: usize },
}

/// Function signature for the scheme-specific signature check. The
/// closure receives `(signer_did, post_state_root, signature)` and
/// returns `true` when the signature is valid. The state root is
/// passed in so the verifier can bind the signature to *this* seal
/// rather than an arbitrary blob — replay-resistance.
pub type SignatureVerifier<'a> = &'a dyn Fn(&str, &str, &str) -> bool;

/// F-ANCHOR-WIT-1: verify a [`SealWitnessChain`] against the local
/// [`TrustBundle`] using `verify_signature` to check each individual
/// signature.
///
/// Rejection rules (in order):
/// 1. `threshold_required == 0` → [`SealSealWitnessError::ThresholdMustBePositive`].
/// 2. `seal_id` empty → [`SealSealWitnessError::MissingSealId`].
/// 3. `witnesses` empty → [`SealSealWitnessError::NoWitnessesProvided`].
/// 4. Repeated `signer_did` → [`SealSealWitnessError::DuplicateSigner`].
/// 5. A signer's domain isn't pinned → [`SealSealWitnessError::UnknownSigner`]. (The trust bundle
///    is the local source of truth for which notaries we'll accept; spec `finality-and-consensus.md
///    §3` explicitly requires this gate.)
/// 6. `verify_signature(signer_did, post_state_root, signature)` returns `false` →
///    [`SealSealWitnessError::SignatureInvalid`].
/// 7. Fewer than `threshold_required` distinct *valid* signers →
///    [`SealSealWitnessError::ThresholdNotMet`].
///
/// On success returns `Ok(distinct_valid_signers)` so the caller can
/// surface a precise audit row.
pub fn verify_seal_witness_chain(
    chain: &SealWitnessChain,
    trust_bundle: &TrustBundle,
    verify_signature: SignatureVerifier<'_>,
) -> Result<usize, SealSealWitnessError> {
    if chain.threshold_required == 0 {
        return Err(SealSealWitnessError::ThresholdMustBePositive);
    }
    if chain.seal_id.trim().is_empty() {
        return Err(SealSealWitnessError::MissingSealId);
    }
    if chain.witnesses.is_empty() {
        return Err(SealSealWitnessError::NoWitnessesProvided);
    }

    let mut seen_signers: BTreeSet<String> = BTreeSet::new();
    let mut valid_signers: usize = 0;
    for witness in &chain.witnesses {
        if !seen_signers.insert(witness.signer_did.clone()) {
            return Err(SealSealWitnessError::DuplicateSigner(
                witness.signer_did.clone(),
            ));
        }
        if trust_bundle.anchor_for(&witness.signer_domain).is_none() {
            return Err(SealSealWitnessError::UnknownSigner {
                signer_did: witness.signer_did.clone(),
                signer_domain: witness.signer_domain.clone(),
            });
        }
        if !verify_signature(
            &witness.signer_did,
            &chain.post_state_root,
            &witness.signature,
        ) {
            return Err(SealSealWitnessError::SignatureInvalid {
                signer_did: witness.signer_did.clone(),
            });
        }
        valid_signers += 1;
    }

    if valid_signers < chain.threshold_required {
        return Err(SealSealWitnessError::ThresholdNotMet {
            required: chain.threshold_required,
            present: valid_signers,
        });
    }

    Ok(valid_signers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::TrustAnchor;

    fn seal(domain: &str, key: &str) -> TrustAnchor {
        TrustAnchor {
            domain: domain.to_owned(),
            public_key: key.to_owned(),
        }
    }

    fn make_bundle() -> TrustBundle {
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(seal("alice.example", "did:web:alice.example"));
        bundle.add_anchor(seal("bob.example", "did:web:bob.example"));
        bundle
    }

    fn make_witness(did: &str, domain: &str, signature: &str) -> SealWitness {
        SealWitness {
            signer_did: did.to_owned(),
            signer_domain: domain.to_owned(),
            signature: signature.to_owned(),
            signed_at: None,
        }
    }

    fn always_valid_verifier() -> impl Fn(&str, &str, &str) -> bool {
        |_, _, _| true
    }

    #[test]
    fn quorum_of_one_with_pinned_signer_passes() {
        let bundle = make_bundle();
        let chain = SealWitnessChain {
            seal_id: "ck:seal:1".to_owned(),
            post_state_root: "sha256:root1".to_owned(),
            witnesses: vec![make_witness(
                "did:web:alice.example",
                "alice.example",
                "sig-1",
            )],
            threshold_required: 1,
        };
        let verifier = always_valid_verifier();
        assert_eq!(verify_seal_witness_chain(&chain, &bundle, &verifier), Ok(1));
    }

    #[test]
    fn quorum_of_two_satisfied_by_two_distinct_pinned_signers() {
        let bundle = make_bundle();
        let chain = SealWitnessChain {
            seal_id: "ck:seal:2".to_owned(),
            post_state_root: "sha256:root2".to_owned(),
            witnesses: vec![
                make_witness("did:web:alice.example", "alice.example", "sig-a"),
                make_witness("did:web:bob.example", "bob.example", "sig-b"),
            ],
            threshold_required: 2,
        };
        let verifier = always_valid_verifier();
        assert_eq!(verify_seal_witness_chain(&chain, &bundle, &verifier), Ok(2));
    }

    #[test]
    fn unknown_signer_domain_is_rejected() {
        let bundle = make_bundle();
        let chain = SealWitnessChain {
            seal_id: "ck:seal:3".to_owned(),
            post_state_root: "sha256:root3".to_owned(),
            witnesses: vec![make_witness(
                "did:web:carol.example",
                "carol.example",
                "sig-c",
            )],
            threshold_required: 1,
        };
        let verifier = always_valid_verifier();
        match verify_seal_witness_chain(&chain, &bundle, &verifier) {
            Err(SealSealWitnessError::UnknownSigner { signer_domain, .. }) => {
                assert_eq!(signer_domain, "carol.example");
            }
            other => panic!("expected UnknownSigner, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_signer_inflates_count_and_is_rejected() {
        let bundle = make_bundle();
        let chain = SealWitnessChain {
            seal_id: "ck:seal:4".to_owned(),
            post_state_root: "sha256:root4".to_owned(),
            witnesses: vec![
                make_witness("did:web:alice.example", "alice.example", "sig-a"),
                make_witness("did:web:alice.example", "alice.example", "sig-a2"),
            ],
            threshold_required: 2,
        };
        let verifier = always_valid_verifier();
        match verify_seal_witness_chain(&chain, &bundle, &verifier) {
            Err(SealSealWitnessError::DuplicateSigner(did)) => {
                assert_eq!(did, "did:web:alice.example");
            }
            other => panic!("expected DuplicateSigner, got {other:?}"),
        }
    }

    #[test]
    fn signature_failure_propagates_specific_signer_did() {
        let bundle = make_bundle();
        let chain = SealWitnessChain {
            seal_id: "ck:seal:5".to_owned(),
            post_state_root: "sha256:root5".to_owned(),
            witnesses: vec![
                make_witness("did:web:alice.example", "alice.example", "good-sig"),
                make_witness("did:web:bob.example", "bob.example", "bad-sig"),
            ],
            threshold_required: 2,
        };
        let verifier = |_signer: &str, _root: &str, signature: &str| signature == "good-sig";
        match verify_seal_witness_chain(&chain, &bundle, &verifier) {
            Err(SealSealWitnessError::SignatureInvalid { signer_did }) => {
                assert_eq!(signer_did, "did:web:bob.example");
            }
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn threshold_not_met_when_fewer_signers_than_required() {
        let bundle = make_bundle();
        let chain = SealWitnessChain {
            seal_id: "ck:seal:6".to_owned(),
            post_state_root: "sha256:root6".to_owned(),
            witnesses: vec![make_witness(
                "did:web:alice.example",
                "alice.example",
                "sig-a",
            )],
            threshold_required: 2,
        };
        let verifier = always_valid_verifier();
        match verify_seal_witness_chain(&chain, &bundle, &verifier) {
            Err(SealSealWitnessError::ThresholdNotMet { required, present }) => {
                assert_eq!(required, 2);
                assert_eq!(present, 1);
            }
            other => panic!("expected ThresholdNotMet, got {other:?}"),
        }
    }

    #[test]
    fn zero_threshold_is_explicitly_rejected() {
        let bundle = make_bundle();
        let chain = SealWitnessChain {
            seal_id: "ck:seal:7".to_owned(),
            post_state_root: "sha256:root7".to_owned(),
            witnesses: vec![make_witness(
                "did:web:alice.example",
                "alice.example",
                "sig-a",
            )],
            threshold_required: 0,
        };
        let verifier = always_valid_verifier();
        match verify_seal_witness_chain(&chain, &bundle, &verifier) {
            Err(SealSealWitnessError::ThresholdMustBePositive) => {}
            other => panic!("expected ThresholdMustBePositive, got {other:?}"),
        }
    }

    #[test]
    fn empty_witness_list_rejected() {
        let bundle = make_bundle();
        let chain = SealWitnessChain {
            seal_id: "ck:seal:8".to_owned(),
            post_state_root: "sha256:root8".to_owned(),
            witnesses: vec![],
            threshold_required: 1,
        };
        let verifier = always_valid_verifier();
        match verify_seal_witness_chain(&chain, &bundle, &verifier) {
            Err(SealSealWitnessError::NoWitnessesProvided) => {}
            other => panic!("expected NoWitnessesProvided, got {other:?}"),
        }
    }

    #[test]
    fn empty_seal_id_rejected() {
        let bundle = make_bundle();
        let chain = SealWitnessChain {
            seal_id: "".to_owned(),
            post_state_root: "sha256:root".to_owned(),
            witnesses: vec![make_witness(
                "did:web:alice.example",
                "alice.example",
                "sig-a",
            )],
            threshold_required: 1,
        };
        let verifier = always_valid_verifier();
        match verify_seal_witness_chain(&chain, &bundle, &verifier) {
            Err(SealSealWitnessError::MissingSealId) => {}
            other => panic!("expected MissingSealId, got {other:?}"),
        }
    }

    #[test]
    fn verifier_sees_post_state_root_so_replay_across_anchors_fails() {
        // Demonstrates that the signature verifier is passed the
        // seal's post-state root — the closure can refuse to
        // accept a signature that was produced against a different
        // root, preventing replay across seals.
        let bundle = make_bundle();
        let chain = SealWitnessChain {
            seal_id: "ck:seal:9".to_owned(),
            post_state_root: "sha256:expected".to_owned(),
            witnesses: vec![make_witness(
                "did:web:alice.example",
                "alice.example",
                "sig-against-different-root",
            )],
            threshold_required: 1,
        };
        let verifier = |_signer: &str, root: &str, signature: &str| {
            // The "real" verifier would re-derive the expected
            // signature from `signer_public_key + root`; this stub
            // demands the signature mention the expected root.
            signature.contains(root)
        };
        match verify_seal_witness_chain(&chain, &bundle, &verifier) {
            Err(SealSealWitnessError::SignatureInvalid { signer_did }) => {
                assert_eq!(signer_did, "did:web:alice.example");
            }
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }
}
