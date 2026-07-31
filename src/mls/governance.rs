//! MLS Governance Binding helpers (`ak.profile.mls_governance_binding.full.v1`).
//!
//! Spec: `crypto-media/encryption-and-audit.md` §10. Every MLS commit MUST
//! carry preconditions binding it to:
//! 1. the previous MLS epoch (`mls_epoch_cell.head_eq(prev_epoch)`) — racing commits fail closed.
//! 2. the group's `covered_seals_cell.contains(required_governance_seal)` — the commit MUST already
//!    cover the governance seal it asserts.
//!
//! What the commit *writes* is no longer producer-authored. v1 deleted the
//! standalone Move object and its `effects[]` channel: the three governance
//! cells an `ak.mls.commit` advances (epoch / key schedule / covered seals) are
//! derived by the receiver from the registered reducer contract over the signed
//! `kind + payload`. Preconditions stay on the Event and stay producer-signed,
//! so only they are built here.
//!
//! All three cells are addressed by `payload.mls_group_id`. A Realm has one MLS
//! group per Circle, so addressing the covered-seals frontier by `realm_id` —
//! as the pre-v1 helper did — merged the frontiers of unrelated groups into one
//! cell.

use arkret_sdk::mls_move::{covered_seals_cell_id, mls_epoch_cell_id};
use arkret_sdk::{Precondition, Predicate, PredicateOp, SealId};
use serde_json::Value;

/// The `ak.profile.mls_governance_binding.full.v1` profile id. Mirrors the
/// hardening profile registered in `spec/v1/artifacts/profiles/conformance-profiles.json`.

/// The two §10 preconditions an `ak.mls.commit` Event MUST carry.
///
/// Both are addressed by the MLS group id, matching the registered
/// `cell_subject` of the cells the commit goes on to write.
pub fn mls_commit_preconditions(
    mls_group_id: &str,
    prev_epoch: u64,
    attested_governance_seal: &SealId,
) -> anyhow::Result<Vec<Precondition>> {
    let epoch_cell = mls_epoch_cell_id(mls_group_id)
        .map_err(|error| anyhow::anyhow!("mls epoch cell id invalid: {error:?}"))?;
    let covered_seals_cell = covered_seals_cell_id(mls_group_id)
        .map_err(|error| anyhow::anyhow!("covered seals cell id invalid: {error:?}"))?;
    Ok(vec![
        Precondition {
            cell: epoch_cell,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(Value::from(prev_epoch)),
                values: None,
                predicate_id: None,
            },
        },
        Precondition {
            cell: covered_seals_cell,
            predicate: Predicate {
                op: PredicateOp::Contains,
                value: Some(Value::String(attested_governance_seal.as_str().to_owned())),
                values: None,
                predicate_id: None,
            },
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal() -> SealId {
        SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap()
    }

    /// The pre-v1 assertion was "two preconditions and three producer
    /// `effects[]`". v1 keeps the preconditions on the Event and derives the
    /// three writes from the registry, so the precondition half is asserted
    /// here; the write half is asserted against the registered contract in
    /// `crate::mls::governance_proof`, which is where the projection is
    /// actually consumed.
    #[test]
    fn commit_preconditions_bind_epoch_and_covered_seal_by_group() {
        let preconditions = mls_commit_preconditions("mls-group-1", 7, &seal()).unwrap();

        assert_eq!(preconditions.len(), 2);
        assert!(preconditions[0].cell.as_str().contains("mls.epoch"));
        assert_eq!(preconditions[0].predicate.op, PredicateOp::HeadEq);
        assert_eq!(preconditions[0].predicate.value, Some(Value::from(7u64)));
        assert!(preconditions[1].cell.as_str().contains("covered_seals"));
        assert_eq!(preconditions[1].predicate.op, PredicateOp::Contains);
        // Both cells are keyed by the MLS group, never by the Realm: a Realm
        // has one group per Circle, and merging their frontiers would let one
        // Circle's coverage satisfy another Circle's commit.
        assert!(preconditions[0].cell.as_str().ends_with("mls-group-1"));
        assert!(preconditions[1].cell.as_str().ends_with("mls-group-1"));
    }
}
