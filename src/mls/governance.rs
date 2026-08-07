//! MLS Governance Binding helpers (`ak.profile.mls_governance_binding.full.v1`).
//!
//! Spec: `authz/event-auth-state-resolution.md` §9.3.1 plus the registered
//! `ak.mls.commit` reducer contract. Every MLS commit MUST
//! carry preconditions binding it to:
//! 1. the previous MLS epoch (`mls_epoch_cell.head_eq(prev_epoch)`) — racing commits fail closed.
//! 2. the previous key-schedule governance binding
//!    (`key_schedule_cell.head_eq(previous_governance_binding)`) — both CAS registers advance from
//!    an exact, accepted predecessor.
//!
//! What the commit *writes* is no longer producer-authored. v1 deleted the
//! standalone Move object and its `effects[]` channel: the three governance
//! cells an `ak.mls.commit` advances (epoch / key schedule) are
//! derived by the receiver from the registered reducer contract over the signed
//! `kind + payload`. Preconditions stay on the Event and stay producer-signed,
//! so only they are built here.
//!
//! Both cells are addressed by `payload.mls_group_id`.

use arkret_sdk::mls_cells::{key_schedule_cell_id, mls_epoch_cell_id};
use arkret_sdk::{Precondition, Predicate, PredicateOp};
use serde_json::Value;

/// The exact predecessor preconditions an `ak.mls.commit` Event MUST carry.
///
/// Both are addressed by the MLS group id, matching the registered
/// `cell_subject` of the cells the commit goes on to write.
pub fn mls_commit_preconditions(
    mls_group_id: &str,
    prev_epoch: u64,
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> anyhow::Result<Vec<Precondition>> {
    let epoch_cell = mls_epoch_cell_id(mls_group_id)
        .map_err(|error| anyhow::anyhow!("mls epoch cell id invalid: {error:?}"))?;
    let key_schedule_cell = key_schedule_cell_id(mls_group_id)
        .map_err(|error| anyhow::anyhow!("key schedule cell id invalid: {error:?}"))?;
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
            cell: key_schedule_cell,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(serde_json::to_value(previous_governance_binding).map_err(
                    |error| anyhow::anyhow!("governance binding encode failed: {error}"),
                )?),
                values: None,
                predicate_id: None,
            },
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn governance_binding() -> arkret_sdk::MlsGovernanceBindingPayload {
        let root = arkret_sdk::Hash::new(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        arkret_sdk::MlsGovernanceBindingPayload::realm(
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-8000-8000-000000000001".to_owned())
                .unwrap(),
            "mls-group-1",
            7,
            7,
            root,
            arkret_sdk::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            arkret_sdk::CORE_REDUCER_PROFILE,
        )
        .unwrap()
    }

    /// The pre-v1 assertion was "two preconditions and three producer
    /// `effects[]`". v1 keeps the preconditions on the Event and derives the
    /// three writes from the registry, so the precondition half is asserted
    /// here; the write half is asserted against the registered contract in
    /// `crate::mls::governance_proof`, which is where the projection is
    /// actually consumed.
    #[test]
    fn commit_preconditions_bind_both_cas_predecessors_by_group() {
        let previous_binding = governance_binding();
        let preconditions = mls_commit_preconditions("mls-group-1", 7, &previous_binding).unwrap();

        assert_eq!(preconditions.len(), 2);
        assert!(preconditions[0].cell.as_str().contains("mls.epoch"));
        assert_eq!(preconditions[0].predicate.op, PredicateOp::HeadEq);
        assert_eq!(preconditions[0].predicate.value, Some(Value::from(7u64)));
        assert!(preconditions[1].cell.as_str().contains("key_schedule"));
        assert_eq!(preconditions[1].predicate.op, PredicateOp::HeadEq);
        assert_eq!(
            preconditions[1].predicate.value,
            Some(serde_json::to_value(&previous_binding).unwrap())
        );
        assert!(preconditions[0].cell.as_str().ends_with("mls-group-1"));
        assert!(preconditions[1].cell.as_str().ends_with("mls-group-1"));
    }
}
